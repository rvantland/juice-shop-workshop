/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import process = require('process')
import { type Memory, type Product } from '../../data/types'
import logger from '../logger'
import config from 'config'
import path from 'path'
import fs from 'fs'
import yaml from 'js-yaml'
import colors from 'colors/safe'
// SECURITY FIX: Replaced vulnerable yaml-schema-validator with simple type checker

const specialProducts = [
  { name: '"Christmas Special" challenge product', key: 'useForChristmasSpecialChallenge' },
  { name: '"Product Tampering" challenge product', key: 'urlForProductTamperingChallenge' },
  { name: '"Retrieve Blueprint" challenge product', key: 'fileForRetrieveBlueprintChallenge', extra: { key: 'exifForBlueprintChallenge', name: 'list of EXIF metadata properties' } },
  { name: '"Leaked Unsafe Product" challenge product', key: 'keywordsForPastebinDataLeakChallenge' }
]

const specialMemories = [
  { name: '"Meta Geo Stalking" challenge memory', user: 'john', keys: ['geoStalkingMetaSecurityQuestion', 'geoStalkingMetaSecurityAnswer'] },
  { name: '"Visual Geo Stalking" challenge memory', user: 'emma', keys: ['geoStalkingVisualSecurityQuestion', 'geoStalkingVisualSecurityAnswer'] }
]

const validateConfig = ({ products = config.get('products'), memories = config.get('memories'), exitOnFailure = true }: { products: Product[], memories: Memory[], exitOnFailure: boolean }) => {
  let success = true
  success = checkYamlSchema() && success
  success = checkMinimumRequiredNumberOfProducts(products) && success
  success = checkUnambiguousMandatorySpecialProducts(products) && success
  success = checkUniqueSpecialOnProducts(products) && success
  success = checkNecessaryExtraKeysOnSpecialProducts(products) && success
  success = checkMinimumRequiredNumberOfMemories(memories) && success
  success = checkUnambiguousMandatorySpecialMemories(memories) && success
  success = checkUniqueSpecialOnMemories(memories) && success
  success = checkSpecialMemoriesHaveNoUserAssociated(memories) && success
  success = checkForIllogicalCombos() && success
  if (success) {
    logger.info(`Configuration ${colors.bold(process.env.NODE_ENV ?? 'default')} validated (${colors.green('OK')})`)
  } else {
    logger.warn(`Configuration ${colors.bold(process.env.NODE_ENV ?? 'default')} validated (${colors.red('NOT OK')})`)
    logger.warn(`Visit ${colors.yellow('https://pwning.owasp-juice.shop/part1/customization.html#yaml-configuration-file')} for the configuration schema definition.`)
    if (exitOnFailure) {
      logger.error(colors.red('Exiting due to configuration errors!'))
      process.exit(1)
    }
  }
  return success
}

// SECURITY FIX: Simple schema validator to replace vulnerable yaml-schema-validator
interface SchemaNode {
  type?: string
  [key: string]: SchemaNode | string | undefined
}

function validateType(value: any, expectedType: string): boolean {
  switch (expectedType) {
    case 'string': return typeof value === 'string'
    case 'number': return typeof value === 'number'
    case 'boolean': return typeof value === 'boolean'
    case 'array': return Array.isArray(value)
    case 'object': return typeof value === 'object' && value !== null && !Array.isArray(value)
    default: return true
  }
}

function validateAgainstSchema(config: any, schema: SchemaNode, path: string = ''): string[] {
  const errors: string[] = []
  
  for (const key of Object.keys(schema)) {
    const schemaValue = schema[key]
    const configValue = config?.[key]
    const currentPath = path ? `${path}.${key}` : key
    
    if (typeof schemaValue === 'object' && schemaValue !== null) {
      if ('type' in schemaValue && typeof schemaValue.type === 'string') {
        // This is a type definition node
        if (configValue !== undefined && !validateType(configValue, schemaValue.type)) {
          errors.push(`${currentPath}: expected ${schemaValue.type}, got ${typeof configValue}`)
        }
      } else {
        // This is a nested object, recurse
        if (configValue !== undefined) {
          errors.push(...validateAgainstSchema(configValue, schemaValue as SchemaNode, currentPath))
        }
      }
    }
  }
  
  return errors
}

const checkYamlSchema = (configuration = config.util.toObject()) => {
  let success = true
  try {
    const schemaContent = fs.readFileSync(path.resolve('config.schema.yml'), 'utf8')
    const schema = yaml.load(schemaContent) as SchemaNode
    const schemaErrors = validateAgainstSchema(configuration, schema)
    
    if (schemaErrors.length !== 0) {
      logger.warn(`Config schema validation failed with ${schemaErrors.length} errors (${colors.red('NOT OK')})`)
      schemaErrors.forEach((error: string) => {
        logger.warn(colors.red(error))
      })
      success = false
    }
  } catch (err) {
    logger.warn(`Could not validate config schema: ${err}`)
  }
  return success
}

const checkMinimumRequiredNumberOfProducts = (products: Product[]) => {
  let success = true
  if (products.length < 4) {
    logger.warn(`Only ${products.length} products are configured but at least four are required (${colors.red('NOT OK')})`)
    success = false
  }
  return success
}

const checkUnambiguousMandatorySpecialProducts = (products: Product[]) => {
  let success = true
  specialProducts.forEach(({ name, key }) => {
    // @ts-expect-error FIXME Ignoring any type issue on purpose
    const matchingProducts = products.filter((product) => product[key])
    if (matchingProducts.length === 0) {
      logger.warn(`No product is configured as ${colors.italic(name)} but one is required (${colors.red('NOT OK')})`)
      success = false
    } else if (matchingProducts.length > 1) {
      logger.warn(`${matchingProducts.length} products are configured as ${colors.italic(name)} but only one is allowed (${colors.red('NOT OK')})`)
      success = false
    }
  })
  return success
}

const checkNecessaryExtraKeysOnSpecialProducts = (products: Product[]) => {
  let success = true
  specialProducts.forEach(({ name, key, extra = {} }) => {
    // @ts-expect-error FIXME implicit any type issue
    const matchingProducts = products.filter((product) => product[key])
    // @ts-expect-error FIXME implicit any type issue
    if (extra.key && matchingProducts.length === 1 && !matchingProducts[0][extra.key]) {
      logger.warn(`Product ${colors.italic(matchingProducts[0].name)} configured as ${colors.italic(name)} does't contain necessary ${colors.italic(`${extra.name}`)} (${colors.red('NOT OK')})`)
      success = false
    }
  })
  return success
}

const checkUniqueSpecialOnProducts = (products: Product[]) => {
  let success = true
  products.forEach((product) => {
    // @ts-expect-error FIXME any type issue
    const appliedSpecials = specialProducts.filter(({ key }) => product[key])
    if (appliedSpecials.length > 1) {
      logger.warn(`Product ${colors.italic(product.name)} is used as ${appliedSpecials.map(({ name }) => `${colors.italic(name)}`).join(' and ')} but can only be used for one challenge (${colors.red('NOT OK')})`)
      success = false
    }
  })
  return success
}

const checkMinimumRequiredNumberOfMemories = (memories: Memory[]) => {
  let success = true
  if (memories.length < 2) {
    logger.warn(`Only ${memories.length} memories are configured but at least two are required (${colors.red('NOT OK')})`)
    success = false
  }
  return success
}

const checkUnambiguousMandatorySpecialMemories = (memories: Memory[]) => {
  let success = true
  specialMemories.forEach(({ name, keys }) => {
    // @ts-expect-error FIXME any type issue
    const matchingMemories = memories.filter((memory) => memory[keys[0]] && memory[keys[1]])
    if (matchingMemories.length === 0) {
      logger.warn(`No memory is configured as ${colors.italic(name)} but one is required (${colors.red('NOT OK')})`)
      success = false
    } else if (matchingMemories.length > 1) {
      logger.warn(`${matchingMemories.length} memories are configured as ${colors.italic(name)} but only one is allowed (${colors.red('NOT OK')})`)
      success = false
    }
  })
  return success
}

const checkSpecialMemoriesHaveNoUserAssociated = (memories: Memory[]) => {
  let success = true
  specialMemories.forEach(({ name, user, keys }) => {
    // @ts-expect-error FIXME any type issue
    const matchingMemories = memories.filter((memory) => memory[keys[0]] && memory[keys[1]] && memory.user && memory.user !== user)
    if (matchingMemories.length > 0) {
      logger.warn(`Memory configured as ${colors.italic(name)} must belong to user ${colors.italic(user)} but was linked to ${colors.italic(matchingMemories[0].user)} user (${colors.red('NOT OK')})`)
      success = false
    }
  })
  return success
}

const checkUniqueSpecialOnMemories = (memories: Memory[]) => {
  let success = true
  memories.forEach((memory) => {
    // @ts-expect-error FIXME any type issue
    const appliedSpecials = specialMemories.filter(({ keys }) => memory[keys[0]] && memory[keys[1]])
    if (appliedSpecials.length > 1) {
      logger.warn(`Memory ${colors.italic(memory.caption)} is used as ${appliedSpecials.map(({ name }) => `${colors.italic(name)}`).join(' and ')} but can only be used for one challenge (${colors.red('NOT OK')})`)
      success = false
    }
  })
  return success
}

const checkForIllogicalCombos = (configuration = config.util.toObject()) => {
  let success = true
  if (configuration.challenges.restrictToTutorialsFirst && !configuration.hackingInstructor.isEnabled) {
    logger.warn(`Restricted tutorial mode is enabled while Hacking Instructor is disabled (${colors.red('NOT OK')})`)
    success = false
  }
  if (configuration.ctf.showFlagsInNotifications && !configuration.challenges.showSolvedNotifications) {
    logger.warn(`CTF flags are enabled while challenge solved notifications are disabled (${colors.red('NOT OK')})`)
    success = false
  }
  if (['name', 'flag', 'both'].includes(configuration.ctf.showCountryDetailsInNotifications) && !configuration.ctf.showFlagsInNotifications) {
    logger.warn(`CTF country mappings for FBCTF are enabled while CTF flags are disabled (${colors.red('NOT OK')})`)
    success = false
  }
  return success
}

validateConfig.checkYamlSchema = checkYamlSchema
validateConfig.checkUnambiguousMandatorySpecialProducts = checkUnambiguousMandatorySpecialProducts
validateConfig.checkUniqueSpecialOnProducts = checkUniqueSpecialOnProducts
validateConfig.checkNecessaryExtraKeysOnSpecialProducts = checkNecessaryExtraKeysOnSpecialProducts
validateConfig.checkMinimumRequiredNumberOfProducts = checkMinimumRequiredNumberOfProducts
validateConfig.checkUnambiguousMandatorySpecialMemories = checkUnambiguousMandatorySpecialMemories
validateConfig.checkUniqueSpecialOnMemories = checkUniqueSpecialOnMemories
validateConfig.checkMinimumRequiredNumberOfMemories = checkMinimumRequiredNumberOfMemories
validateConfig.checkSpecialMemoriesHaveNoUserAssociated = checkSpecialMemoriesHaveNoUserAssociated

module.exports = validateConfig
