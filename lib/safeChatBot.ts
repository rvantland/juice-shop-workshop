/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// SECURITY FIX: Safe chatbot replacement for vulnerable juicy-chat-bot (vm2)

interface TrainingUtterance {
  intent: string
  utterances: string[]
  answers: Array<{
    action: string
    body?: string
    handler?: string
  }>
}

interface TrainingData {
  lang: string
  data: TrainingUtterance[]
}

interface UserData {
  name: string
  lastInteraction: number
}

interface BotResponse {
  action: string
  body?: string
  handler?: string
}

export class SafeBot {
  public name: string
  public greeting: string
  public defaultResponse: string
  public training: { state: boolean }
  
  private trainingData: TrainingData | null = null
  private users: Map<string, UserData> = new Map()

  constructor(name: string, greeting: string, trainingSet: string, defaultResponse: string) {
    this.name = name
    this.greeting = greeting
    this.defaultResponse = defaultResponse
    this.training = { state: false }
    
    try {
      this.trainingData = JSON.parse(trainingSet)
    } catch {
      this.trainingData = null
    }
  }

  async train(): Promise<void> {
    // Simple training - just validate the data is loaded
    if (this.trainingData && this.trainingData.data && this.trainingData.data.length > 0) {
      this.training.state = true
    }
  }

  addUser(userId: string, username: string): void {
    this.users.set(userId, {
      name: username,
      lastInteraction: Date.now()
    })
  }

  greet(userId: string): string {
    const user = this.users.get(userId)
    const name = user?.name || 'friend'
    return this.greeting.replace(/<customer-name>/g, name)
  }

  // Safe method to check if user exists (replaces vulnerable factory.run)
  currentUser(userId: string): string | null {
    const user = this.users.get(userId)
    return user?.name || null
  }

  async respond(query: string, userId: string): Promise<BotResponse> {
    if (!this.trainingData || !this.training.state) {
      return { action: 'response', body: this.defaultResponse }
    }

    const user = this.users.get(userId)
    const normalizedQuery = query.toLowerCase().trim()

    // Find the best matching intent
    let bestMatch: TrainingUtterance | null = null
    let bestScore = 0

    for (const item of this.trainingData.data) {
      for (const utterance of item.utterances) {
        const score = this.matchScore(normalizedQuery, utterance.toLowerCase())
        if (score > bestScore) {
          bestScore = score
          bestMatch = item
        }
      }
    }

    // If we found a good match (threshold > 0.5)
    if (bestMatch && bestScore > 0.5) {
      const answers = bestMatch.answers
      const answer = answers[Math.floor(Math.random() * answers.length)]
      
      if (answer.action === 'function' && answer.handler) {
        return { action: 'function', handler: answer.handler }
      }
      
      let body = answer.body || this.defaultResponse
      // Replace placeholders
      if (user) {
        body = body.replace(/<customer-name>/g, user.name)
      }
      
      return { action: 'response', body }
    }

    return { action: 'response', body: this.defaultResponse }
  }

  // Simple matching score based on word overlap
  private matchScore(query: string, utterance: string): number {
    // Handle exact match
    if (query === utterance) return 1

    // Handle wildcard patterns (e.g., "how much is X")
    const wildcardPattern = utterance.replace(/\bX\b/gi, '.*').replace(/\bY\b/gi, '.*')
    const regex = new RegExp(`^${wildcardPattern}$`, 'i')
    if (regex.test(query)) return 0.9

    // Word overlap scoring
    const queryWords = new Set(query.split(/\s+/).filter(w => w.length > 2))
    const utteranceWords = new Set(utterance.split(/\s+/).filter(w => w.length > 2))
    
    if (queryWords.size === 0 || utteranceWords.size === 0) return 0

    let matches = 0
    for (const word of queryWords) {
      if (utteranceWords.has(word)) matches++
    }

    return matches / Math.max(queryWords.size, utteranceWords.size)
  }
}

module.exports = { SafeBot }

