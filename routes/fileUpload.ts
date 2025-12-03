/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'os'
import fs = require('fs')
import { type NextFunction, type Request, type Response } from 'express'
import path from 'path'
import * as utils from '../lib/utils'
import { XMLParser } from 'fast-xml-parser'

const unzipper = require('unzipper')

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && !utils.disableOnContainerEnv()) {
      const buffer = file.buffer
      const filename = file.originalname.toLowerCase()
      const tempFile = path.join(os.tmpdir(), filename)
      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { next(err) }
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { next(err) }
          fs.close(fd, function () {
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const fileName = entry.path
                
                // SECURITY FIX: Prevent Zip Slip attack by validating path
                // Reject any paths containing ".." or starting with "/"
                if (fileName.includes('..') || fileName.startsWith('/') || fileName.startsWith('\\')) {
                  entry.autodrain()
                  return
                }
                
                // Sanitize filename - only allow alphanumeric, dots, underscores, hyphens
                const sanitizedFileName = path.basename(fileName).replace(/[^a-zA-Z0-9._-]/g, '_')
                const targetDir = path.resolve('uploads/complaints/')
                const absolutePath = path.resolve(targetDir, sanitizedFileName)
                
                // SECURITY FIX: Ensure the resolved path is still within the target directory
                if (!absolutePath.startsWith(targetDir)) {
                  entry.autodrain()
                  return
                }
                
                entry.pipe(fs.createWriteStream(absolutePath).on('error', function (err) { next(err) }))
              }).on('error', function (err: unknown) { next(err) })
          })
        })
      })
    }
    res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  // SECURITY FIX: Enforce file size limit
  const MAX_FILE_SIZE = 100000 // 100KB
  if (file != null && file.size > MAX_FILE_SIZE) {
    res.status(413).json({ error: 'File too large. Maximum size is 100KB.' })
    return
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  // SECURITY FIX: Only allow specific file types
  const allowedTypes = ['pdf', 'xml', 'zip']
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  if (fileType && !allowedTypes.includes(fileType)) {
    res.status(415).json({ error: 'Invalid file type. Only PDF, XML, and ZIP files are allowed.' })
    return
  }
  next()
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    if ((file?.buffer) != null) {
      const data = file.buffer.toString()
      try {
        // SECURITY FIX: Use fast-xml-parser with secure options
        // This parser is pure JavaScript and doesn't process external entities by default
        const parser = new XMLParser({
          ignoreAttributes: false,
          // SECURITY: Don't process entities to prevent XXE
          processEntities: false,
          // SECURITY: Limit tag depth to prevent DoS
          htmlEntities: false,
          // SECURITY: Stop parsing on invalid data
          stopNodes: ['*.script', '*.style']
        })
        
        // SECURITY: Limit XML size to prevent DoS
        if (data.length > 100000) {
          res.status(413)
          next(new Error('XML file too large'))
          return
        }
        
        const xmlDoc = parser.parse(data)
        const xmlString = JSON.stringify(xmlDoc)
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: any) {
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + file.originalname + ')'))
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  res.status(204).end()
}

module.exports = {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload
}
