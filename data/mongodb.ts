/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// SECURITY FIX: Replaced marsdb (command injection vulnerability) with lokijs
import Loki, { Collection } from 'lokijs'

const loki = new Loki('juice-shop.db')

// Create collections with MongoDB-like API wrapper
const reviewsCollection = loki.addCollection('reviews', { indices: ['product', 'author'] })
const ordersCollection = loki.addCollection('orders', { indices: ['oderId', 'email'] })

// Wrapper to provide MongoDB-like API for compatibility
function createCollectionWrapper(collection: Collection<any>) {
  return {
    find: (query: any = {}) => {
      return Promise.resolve().then(() => {
        // Handle $where queries by converting to regular queries
        if (query.$where) {
          // $where is unsafe - convert to safe query if possible
          console.warn('$where queries are not supported for security reasons')
          return []
        }
        
        // Convert MongoDB query to LokiJS query
        const lokiQuery: any = {}
        for (const key of Object.keys(query)) {
          if (key.startsWith('$')) continue // Skip operators
          lokiQuery[key] = query[key]
        }
        
        return collection.find(lokiQuery)
      })
    },
    findOne: (query: any) => {
      return Promise.resolve().then(() => {
        const lokiQuery: any = {}
        for (const key of Object.keys(query)) {
          if (key.startsWith('$')) continue
          lokiQuery[key] = query[key]
        }
        return collection.findOne(lokiQuery)
      })
    },
    insert: (doc: any) => {
      return Promise.resolve().then(() => {
        const inserted = collection.insert(doc)
        return { ops: [inserted], insertedId: inserted.$loki }
      })
    },
    update: (query: any, update: any, options: any = {}) => {
      return Promise.resolve().then(() => {
        const lokiQuery: any = {}
        for (const key of Object.keys(query)) {
          if (key.startsWith('$')) continue
          lokiQuery[key] = query[key]
        }
        
        const docs = options.multi ? collection.find(lokiQuery) : [collection.findOne(lokiQuery)].filter(Boolean)
        const original = docs.map((d: any) => ({ ...d }))
        
        docs.forEach((doc: any) => {
          if (update.$set) {
            Object.assign(doc, update.$set)
          }
          collection.update(doc)
        })
        
        return { modified: docs.length, original }
      })
    },
    remove: (query: any) => {
      return Promise.resolve().then(() => {
        const lokiQuery: any = {}
        for (const key of Object.keys(query)) {
          if (key.startsWith('$')) continue
          lokiQuery[key] = query[key]
        }
        const docs = collection.find(lokiQuery)
        docs.forEach((doc: any) => collection.remove(doc))
        return { removed: docs.length }
      })
    }
  }
}

const db = {
  reviews: createCollectionWrapper(reviewsCollection),
  orders: createCollectionWrapper(ordersCollection)
}

module.exports = db
