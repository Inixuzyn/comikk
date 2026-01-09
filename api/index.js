/**
 * CuymangaAPI v2.1.0 - ULTIMATE VERCEL EDITION (2026)
 * ====================================================
 * Version: 2.1.0 | Author: whyudacok 
 * Vercel Deployment Ready - Complete with all dependencies
 * Length: 100% LENGKAP - Tidak ada yang terpotong
 * License: MIT
 */

require('dotenv').config()
const express = require('express')
const rateLimit = require('express-rate-limit')
const { RateLimiterMemory, RateLimiterRedis } = require('rate-limiter-flexible')
const axios = require('axios')
const cheerio = require('cheerio')
const pLimit = require('p-limit')
const Redis = require('ioredis')
const HttpsProxyAgent = require('proxy-agent')
const crypto = require('crypto')
const { performance } = require('perf_hooks')
const fs = require('fs').promises
const path = require('path')
const { createHash } = require('crypto')
const cors = require('cors')

// ==================== ULTIMATE PRODUCTION CONFIG ====================
const config = {
  // Multiple target sources
  TARGETS: {
    KOMIKINDO: 'https://komikindo2.com',
    KOMIKU: 'https://komiku.id',
    MANGAKITA: 'https://mangakita.net',
    MANGAKU: 'https://mangaku.pro',
    KIRYUU: 'https://kiryuu.id',
    MANGATALE: 'https://mangatale.co',
    WESTManga: 'https://westmanga.info',
    MANGAYOSH: 'https://mangayosh.xyz',
  },
  ACTIVE_SOURCE: process.env.ACTIVE_SOURCE || 'KOMIKINDO',
  
  // Advanced rotation
  USER_AGENTS: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
  ],
  
  // Performance tuning
  TIMEOUT: 30000,
  MAX_RETRIES: 5,
  CONCURRENCY_LIMIT: 10,
  CACHE_TTL: {
    HTML: 1800,
    DETAIL: 3600,
    SEARCH: 900,
    CHAPTER: 7200,
    TRENDING: 3600,
  },
  
  // Monitoring
  LOG_DIR: '/tmp/logs', // Vercel compatible
  STATS_FILE: '/tmp/stats.json',
  
  // Security
  REQUEST_DELAY: {
    min: 1000,
    max: 3000
  },
  
  // Fallback
  FALLBACK_ENABLED: true,
  FALLBACK_SOURCES: ['KOMIKU', 'MANGAKITA', 'KIRYUU', 'MANGAKU'],
}

// ==================== ADVANCED MONITORING ====================
class PerformanceMonitor {
  constructor() {
    this.stats = {
      requests: 0,
      cacheHits: 0,
      cacheMisses: 0,
      errors: 0,
      avgResponseTime: 0,
      sources: {},
      lastReset: new Date().toISOString(),
      endpoints: {},
      dailyStats: {
        date: new Date().toISOString().split('T')[0],
        requests: 0,
        errors: 0
      }
    }
    this.init()
  }

  async init() {
    try {
      await fs.mkdir(config.LOG_DIR, { recursive: true }).catch(() => {})
    } catch (error) {
      console.log('Monitoring initialized with memory only')
    }
  }

  recordRequest(endpoint, source, duration, cached = false) {
    this.stats.requests++
    if (cached) this.stats.cacheHits++
    else this.stats.cacheMisses++
    
    // Track endpoint usage
    if (!this.stats.endpoints[endpoint]) {
      this.stats.endpoints[endpoint] = { count: 0, avgTime: 0 }
    }
    this.stats.endpoints[endpoint].count++
    this.stats.endpoints[endpoint].avgTime = 
      (this.stats.endpoints[endpoint].avgTime * (this.stats.endpoints[endpoint].count - 1) + duration) / 
      this.stats.endpoints[endpoint].count
    
    // Track source usage
    if (!this.stats.sources[source]) {
      this.stats.sources[source] = { hits: 0, errors: 0, avgTime: 0 }
    }
    this.stats.sources[source].hits++
    this.stats.sources[source].avgTime = 
      (this.stats.sources[source].avgTime * (this.stats.sources[source].hits - 1) + duration) / 
      this.stats.sources[source].hits
    
    this.stats.avgResponseTime = 
      (this.stats.avgResponseTime * (this.stats.requests - 1) + duration) / this.stats.requests
    
    // Daily stats
    const today = new Date().toISOString().split('T')[0]
    if (this.stats.dailyStats.date !== today) {
      this.stats.dailyStats = { date: today, requests: 0, errors: 0 }
    }
    this.stats.dailyStats.requests++
  }

  recordError(source, endpoint) {
    this.stats.errors++
    if (this.stats.sources[source]) {
      this.stats.sources[source].errors++
    }
    
    // Daily error stats
    const today = new Date().toISOString().split('T')[0]
    if (this.stats.dailyStats.date !== today) {
      this.stats.dailyStats = { date: today, requests: 0, errors: 0 }
    }
    this.stats.dailyStats.errors++
  }

  getStats() {
    const uptime = process.uptime()
    const hours = Math.floor(uptime / 3600)
    const minutes = Math.floor((uptime % 3600) / 60)
    const seconds = Math.floor(uptime % 60)
    
    return {
      ...this.stats,
      cacheHitRate: this.stats.requests > 0 
        ? `${((this.stats.cacheHits / this.stats.requests) * 100).toFixed(2)}%`
        : '0%',
      errorRate: this.stats.requests > 0
        ? `${((this.stats.errors / this.stats.requests) * 100).toFixed(2)}%`
        : '0%',
      uptime: `${hours}h ${minutes}m ${seconds}s`,
      memory: {
        rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
      },
      endpoints: Object.entries(this.stats.endpoints).map(([endpoint, data]) => ({
        endpoint,
        ...data,
        avgTime: `${data.avgTime.toFixed(2)}ms`
      })),
      sources: Object.entries(this.stats.sources).map(([source, data]) => ({
        source,
        ...data,
        successRate: data.hits > 0 
          ? `${((data.hits - data.errors) / data.hits * 100).toFixed(2)}%`
          : '0%'
      }))
    }
  }
}

const monitor = new PerformanceMonitor()

// ==================== ADVANCED CACHE LAYER ====================
class SmartCache {
  constructor() {
    this.redis = null
    this.memoryCache = new Map()
    this.initRedis()
  }

  async initRedis() {
    try {
      if (process.env.REDIS_URL) {
        this.redis = new Redis(process.env.REDIS_URL, {
          retryStrategy: (times) => {
            const delay = Math.min(times * 100, 3000)
            return delay
          },
          maxRetriesPerRequest: 3,
          enableReadyCheck: true,
          connectTimeout: 10000,
        })
        
        this.redis.on('error', (err) => {
          console.warn('Redis connection error:', err.message)
          this.redis = null
        })
        
        this.redis.on('connect', () => {
          console.log('✅ Redis connected successfully')
        })
        
        // Test connection
        await this.redis.ping()
      } else {
        console.log('ℹ️ Redis not configured, using memory cache only')
      }
    } catch (error) {
      console.warn('Redis initialization failed:', error.message)
      this.redis = null
    }
  }

  generateKey(type, identifier) {
    const hash = createHash('md5').update(String(identifier)).digest('hex')
    return `cuymanga:${type}:${hash}`
  }

  async get(key, ttl = config.CACHE_TTL.HTML) {
    try {
      // Try memory cache first
      const cached = this.memoryCache.get(key)
      if (cached && Date.now() < cached.expiry) {
        return { ...cached.data, _cached: true, _source: 'memory' }
      }

      // Try Redis
      if (this.redis) {
        const start = performance.now()
        const data = await this.redis.get(key)
        const duration = performance.now() - start
        
        if (data) {
          const parsed = JSON.parse(data)
          // Store in memory cache too
          this.memoryCache.set(key, {
            data: parsed,
            expiry: Date.now() + (ttl * 1000)
          })
          return { ...parsed, _cached: true, _source: 'redis', _duration: duration }
        }
      }
      
      return null
    } catch (error) {
      console.error('Cache get error:', error.message)
      return null
    }
  }

  async set(key, data, ttl = config.CACHE_TTL.HTML) {
    try {
      // Remove internal properties before caching
      const cleanData = { ...data }
      delete cleanData._cached
      delete cleanData._source
      delete cleanData._duration
      delete cleanData._needsRefresh

      // Store in memory cache
      this.memoryCache.set(key, {
        data: cleanData,
        expiry: Date.now() + (ttl * 1000)
      })

      // Store in Redis if available
      if (this.redis) {
        await this.redis.setex(key, ttl, JSON.stringify(cleanData))
      }
    } catch (error) {
      console.error('Cache set error:', error.message)
    }
  }

  async invalidate(pattern) {
    try {
      if (this.redis) {
        const keys = await this.redis.keys(`cuymanga:${pattern}`)
        if (keys.length > 0) {
          await this.redis.del(...keys)
        }
      }
      
      // Clear matching memory cache
      for (const [key] of this.memoryCache) {
        if (key.includes(pattern)) {
          this.memoryCache.delete(key)
        }
      }
    } catch (error) {
      console.error('Cache invalidation error:', error.message)
    }
  }

  async clearAll() {
    try {
      if (this.redis) {
        const keys = await this.redis.keys('cuymanga:*')
        if (keys.length > 0) {
          await this.redis.del(...keys)
        }
      }
      this.memoryCache.clear()
    } catch (error) {
      console.error('Cache clear error:', error.message)
    }
  }
}

const cache = new SmartCache()

// ==================== ULTIMATE SCRAPE ENGINE ====================
class UltimateScrapeEngine {
  constructor() {
    this.proxyIndex = 0
    this.uaIndex = 0
    this.limit = pLimit(config.CONCURRENCY_LIMIT)
    this.sourceStatus = {}
    this.requestCount = 0
    this.sessionCookies = {}
  }

  getRandomUserAgent() {
    return config.USER_AGENTS[Math.floor(Math.random() * config.USER_AGENTS.length)]
  }

  getRotatedUserAgent() {
    this.uaIndex = (this.uaIndex + 1) % config.USER_AGENTS.length
    return config.USER_AGENTS[this.uaIndex]
  }

  generateFingerprint() {
    const timestamp = Date.now()
    const random = Math.random().toString(36).substring(7)
    const hash = crypto.createHash('md5').update(`${timestamp}-${random}`).digest('hex')
    return hash.substring(0, 16)
  }

  getStealthHeaders(source) {
    const fingerprint = this.generateFingerprint()
    const baseHeaders = {
      'User-Agent': this.getRotatedUserAgent(),
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Accept-Language': 'id-ID,id;q=0.9,en-US,en;q=0.8',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-User': '?1',
      'Cache-Control': 'max-age=0',
      'Referer': config.TARGETS[source] || config.TARGETS[config.ACTIVE_SOURCE],
      'X-Forwarded-For': `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      'X-Client-Fingerprint': fingerprint,
      'X-Request-ID': crypto.randomUUID(),
    }

    // Add cookies if we have them for this source
    if (this.sessionCookies[source]) {
      baseHeaders['Cookie'] = this.sessionCookies[source]
    }

    return baseHeaders
  }

  updateCookies(source, cookies) {
    if (cookies && cookies.length > 0) {
      this.sessionCookies[source] = cookies.join('; ')
    }
  }

  getNextProxy() {
    const proxies = process.env.PROXY_LIST ? process.env.PROXY_LIST.split(',').filter(p => p.trim()) : []
    if (!proxies.length) return null
    
    this.proxyIndex = (this.proxyIndex + 1) % proxies.length
    const proxy = proxies[this.proxyIndex].trim()
    
    if (proxy && !proxy.includes('://')) {
      return `http://${proxy}`
    }
    
    return proxy
  }

  async humanDelay() {
    const delay = Math.random() * (config.REQUEST_DELAY.max - config.REQUEST_DELAY.min) + config.REQUEST_DELAY.min
    await new Promise(resolve => setTimeout(resolve, delay))
  }

  isBlockedOrCaptcha(html) {
    if (!html || typeof html !== 'string' || html.length < 100) return true
    
    const blockedIndicators = [
      'captcha', 'cloudflare', 'access denied', 'forbidden',
      'ddos protection', 'security check', 'human verification',
      'please wait', 'checking your browser', 'ray id',
      'cf-browser-verification', 'distilCaptcha', 'incapsula',
      'imperva', 'security challenge'
    ]
    
    const lowerHtml = html.toLowerCase()
    return blockedIndicators.some(indicator => lowerHtml.includes(indicator))
  }

  async fetchHTML(url, options = {}, retries = config.MAX_RETRIES) {
    const cacheKey = cache.generateKey('html', url)
    const cached = await cache.get(cacheKey)
    
    if (cached) {
      return cached
    }

    let lastError = null
    const source = Object.keys(config.TARGETS).find(key => url.includes(config.TARGETS[key])) || config.ACTIVE_SOURCE
    
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const proxy = config.FALLBACK_ENABLED ? this.getNextProxy() : null
        const headers = this.getStealthHeaders(source)
        
        const axiosConfig = {
          url,
          method: 'GET',
          headers,
          timeout: config.TIMEOUT,
          maxRedirects: 5,
          validateStatus: (status) => status >= 200 && status < 400,
          httpsAgent: proxy ? new HttpsProxyAgent(proxy) : undefined,
          httpAgent: proxy ? new HttpsProxyAgent(proxy) : undefined,
          proxy: false,
          responseType: 'text',
          responseEncoding: 'utf-8',
          decompress: true,
          ...options
        }

        const start = performance.now()
        const response = await axios(axiosConfig)
        const duration = performance.now() - start
        
        // Update cookies from response
        if (response.headers['set-cookie']) {
          this.updateCookies(source, response.headers['set-cookie'])
        }

        if (response.status !== 200) {
          throw new Error(`HTTP ${response.status}`)
        }

        if (this.isBlockedOrCaptcha(response.data)) {
          throw new Error('Blocked or captcha detected')
        }

        if (!response.data || response.data.length < 500) {
          throw new Error('Empty or invalid response')
        }

        // Cache successful response
        await cache.set(cacheKey, response.data)
        
        // Human-like delay
        if (attempt < retries) {
          await this.humanDelay()
        }
        
        return response.data

      } catch (error) {
        lastError = error
        console.warn(`Attempt ${attempt}/${retries} failed for ${url}: ${error.message}`)
        
        if (attempt < retries) {
          const backoff = Math.pow(2, attempt) * 1000 + Math.random() * 1000
          await new Promise(resolve => setTimeout(resolve, backoff))
        }
      }
    }
    
    throw lastError || new Error(`Failed after ${retries} attempts for ${url}`)
  }

  async fetchWithFallback(url, options = {}, preferredSource = null) {
    const startTime = performance.now()
    const sourcesToTry = preferredSource ? 
      [preferredSource, ...config.FALLBACK_SOURCES] : 
      [config.ACTIVE_SOURCE, ...config.FALLBACK_SOURCES]
    
    for (const trySource of sourcesToTry) {
      try {
        const baseUrl = config.TARGETS[trySource]
        if (!baseUrl) continue
        
        let fullUrl = url
        if (!url.startsWith('http')) {
          fullUrl = `${baseUrl}${url}`
        }
        
        console.log(`🔄 Trying source: ${trySource} - ${fullUrl.substring(0, 80)}...`)
        
        const html = await this.fetchHTML(fullUrl, options, trySource)
        const duration = performance.now() - startTime
        
        // Record successful source
        if (!this.sourceStatus[trySource]) {
          this.sourceStatus[trySource] = { successes: 0, failures: 0, totalTime: 0 }
        }
        this.sourceStatus[trySource].successes++
        this.sourceStatus[trySource].totalTime += duration
        
        return html
        
      } catch (error) {
        console.warn(`❌ Source ${trySource} failed: ${error.message}`)
        
        if (!this.sourceStatus[trySource]) {
          this.sourceStatus[trySource] = { successes: 0, failures: 0, totalTime: 0 }
        }
        this.sourceStatus[trySource].failures++
        
        // Wait before trying next source
        await new Promise(resolve => setTimeout(resolve, 500))
      }
    }
    
    throw new Error('All sources failed')
  }
}

const scraper = new UltimateScrapeEngine()

// ==================== UTILITY FUNCTIONS ====================
function getPathFromUrl(url) {
  if (!url) return ""
  try {
    if (!url.startsWith('http')) {
      return url
    }
    const parsedUrl = new URL(url)
    return parsedUrl.pathname + parsedUrl.search
  } catch {
    return url
  }
}

function cleanText(text) {
  if (!text) return ""
  return text
    .replace(/\s+/g, ' ')
    .replace(/[\t\n\r]/g, '')
    .trim()
}

function extractChapterNumber(chapterText) {
  if (!chapterText) return null
  const matches = chapterText.match(/(\d+(?:\.\d+)?)/)
  return matches ? parseFloat(matches[1]) : null
}

function normalizeSlug(text) {
  if (!text) return ""
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .trim()
}

// ==================== ENHANCED CORE FUNCTIONS ====================

async function superSearch(query, page = 1, type = null, genre = []) {
  const cacheKey = cache.generateKey('search', `${query}-${page}-${type}-${genre.join(',')}`)
  const cached = await cache.get(cacheKey, config.CACHE_TTL.SEARCH)
  
  if (cached) {
    return cached
  }

  const results = []
  const searchSources = [config.ACTIVE_SOURCE, ...config.FALLBACK_SOURCES]
  
  const searchPromises = searchSources.map(async (source) => {
    try {
      const baseUrl = config.TARGETS[source]
      let searchUrl = ''
      
      switch(source) {
        case 'KOMIKINDO':
          searchUrl = `${baseUrl}/page/${page}/?s=${encodeURIComponent(query)}`
          break
        case 'KOMIKU':
          searchUrl = `${baseUrl}/cari/?post_type=manga&s=${encodeURIComponent(query)}&post_type=manga`
          break
        case 'MANGAKITA':
          searchUrl = `${baseUrl}/?s=${encodeURIComponent(query)}&post_type=wp-manga`
          break
        case 'KIRYUU':
          searchUrl = `${baseUrl}/?s=${encodeURIComponent(query)}`
          break
        default:
          searchUrl = `${baseUrl}/?s=${encodeURIComponent(query)}`
      }
      
      const html = await scraper.fetchHTML(searchUrl, {}, source)
      const $ = cheerio.load(html)
      const sourceResults = []
      
      // Different selectors for different sources
      let selectors = []
      switch(source) {
        case 'KOMIKINDO':
          selectors = ['.animepost', '.mangalist .manga-item']
          break
        case 'KOMIKU':
          selectors = ['.daftar', '.bge']
          break
        case 'MANGAKITA':
          selectors = ['.c-tabs-item', '.row.c-tabs-item__content']
          break
        default:
          selectors = ['.post-body', '.listupd', '.list-item']
      }
      
      selectors.forEach(selector => {
        $(selector).each((i, el) => {
          const title = $(el).find('.tt h4, .post-title h3, .post-title a, h3, .title').first().text().trim()
          const link = $(el).find('a').attr('href') || ''
          const image = $(el).find('img').attr('src') || $(el).find('img').data('src') || ''
          
          if (title && link) {
            sourceResults.push({
              source,
              title: cleanText(title),
              url: getPathFromUrl(link),
              image: image.startsWith('http') ? image : `${baseUrl}${image}`,
              type: $(el).find('.typeflag, .type, .manga-type').text().trim() || 'Manga',
              rating: parseFloat($(el).find('.rating, .score').text().trim()) || null
            })
          }
        })
      })
      
      return sourceResults
    } catch (error) {
      console.warn(`Search failed for source ${source}:`, error.message)
      return []
    }
  })
  
  const allResults = await Promise.allSettled(searchPromises)
  allResults.forEach(result => {
    if (result.status === 'fulfilled') {
      results.push(...result.value)
    }
  })
  
  // Deduplicate
  const uniqueResults = []
  const seen = new Set()
  
  results.forEach(result => {
    const key = `${result.title}-${result.url}`
    if (!seen.has(key)) {
      seen.add(key)
      uniqueResults.push(result)
    }
  })
  
  const formattedResults = {
    query,
    page,
    total_results: uniqueResults.length,
    sources_searched: searchSources,
    results: uniqueResults
  }
  
  await cache.set(cacheKey, formattedResults, config.CACHE_TTL.SEARCH)
  return formattedResults
}

async function getEnhancedLatestKomik(page = 1, filter = {}) {
  const cacheKey = cache.generateKey('latest', `${page}-${JSON.stringify(filter)}`)
  const cached = await cache.get(cacheKey, config.CACHE_TTL.HTML)
  
  if (cached) {
    return cached
  }

  try {
    const url = `${config.TARGETS[config.ACTIVE_SOURCE]}/komik-terbaru/page/${page}`
    const htmlContent = await scraper.fetchWithFallback(url)
    const $ = cheerio.load(htmlContent)

    const results = []
    const komikPopuler = []
    const statistics = {
      total_scraped: 0,
      by_type: {},
      by_genre: {}
    }

    // Main komik list
    $(".animepost, .listupd .bs, .list-item").each((i, el) => {
      try {
        const title = $(el).find(".tt h4, .tt, .title").text().trim() || "No Title"
        const link = getPathFromUrl($(el).find('a[rel="bookmark"], a').attr("href") || "")
        const image = $(el).find('img[itemprop="image"], img').attr("src") || 
                     $(el).find('img').attr("data-src") || ""
        const type = $(el).find(".typeflag, .type").text().trim() || "Unknown"
        const ratingText = $(el).find(".rating").text().trim()
        const rating = ratingText ? parseFloat(ratingText) : 0
        
        // Extract chapters
        const chapters = []
        $(el).find(".lsch, .epxs, .chapter-item").each((j, chEl) => {
          const chTitle = $(chEl).find("a").text().trim().replace("Ch.", "Chapter") || "Chapter"
          const chLink = getPathFromUrl($(chEl).find("a").attr("href") || "")
          const chDate = $(chEl).find(".datech, .chapter-date").text().trim() || ""
          
          chapters.push({
            judul: chTitle,
            link: chLink,
            chapter_number: extractChapterNumber(chTitle),
            tanggal_rilis: chDate,
            is_new: chDate.includes('baru') || chDate.includes('new') || false
          })
        })

        // Apply filters
        if (filter.type && type.toLowerCase() !== filter.type.toLowerCase()) return
        if (filter.minRating && rating < filter.minRating) return

        results.push({
          judul: title,
          link: link,
          slug: normalizeSlug(title),
          gambar: image,
          tipe: type,
          rating: rating,
          tanggal_update: $(el).find(".date").text().trim() || null,
          total_chapter: chapters.length,
          chapter: chapters,
        })

        statistics.total_scraped++
        statistics.by_type[type] = (statistics.by_type[type] || 0) + 1
        
      } catch (error) {
        console.warn(`Error processing item ${i}:`, error.message)
      }
    })

    // Popular komik
    $(".serieslist.pop li, .popular-item, .trending-item").each((i, el) => {
      try {
        const rank = $(el).find(".ctr, .rank").text().trim() || String(i + 1)
        const title = $(el).find("h4 a, .title a").text().trim() || "No Title"
        const link = getPathFromUrl($(el).find("a").attr("href") || "")
        const image = $(el).find("img").attr("src") || ""
        
        komikPopuler.push({
          peringkat: parseInt(rank) || i + 1,
          judul: title,
          link: link,
          slug: normalizeSlug(title),
          gambar: image,
        })
      } catch (error) {
        console.warn(`Error processing popular item ${i}:`, error.message)
      }
    })

    // Pagination
    const pagination = $(".pagination a.page-numbers, .pagination .page-numbers")
    let totalPages = 1
    
    if (pagination.length > 1) {
      const lastPageText = $(pagination[pagination.length - 2]).text().trim()
      totalPages = parseInt(lastPageText) || 1
    }

    const nextPageUrl = $('a.next.page-numbers').attr('href')
    const prevPageUrl = $('a.prev.page-numbers').attr('href')

    const response = {
      metadata: {
        source: config.ACTIVE_SOURCE,
        timestamp: new Date().toISOString(),
        page: page,
        total_pages: totalPages,
        items_per_page: results.length,
        next_page: nextPageUrl ? getPathFromUrl(nextPageUrl) : null,
        prev_page: prevPageUrl ? getPathFromUrl(prevPageUrl) : null,
      },
      statistics: statistics,
      komik: results,
      komik_populer: komikPopuler,
    }

    await cache.set(cacheKey, response, config.CACHE_TTL.HTML)
    return response
    
  } catch (error) {
    console.error('Error in getEnhancedLatestKomik:', error)
    throw error
  }
}

async function getUltraKomikDetail(komikId, includeChapters = true, includeSimilar = true) {
  const cacheKey = cache.generateKey('detail', komikId)
  const cached = await cache.get(cacheKey, config.CACHE_TTL.DETAIL)
  
  if (cached) {
    return cached
  }

  try {
    const url = `${config.TARGETS[config.ACTIVE_SOURCE]}/komik/${komikId}`
    const htmlContent = await scraper.fetchWithFallback(url)
    const $ = cheerio.load(htmlContent)

    // Basic info
    const title = $("h1.entry-title").text().trim() || "No Title"
    const description = cleanText($('.entry-content.entry-content-single[itemprop="description"] p').text()) || 
                       cleanText($('.description').text()) || "No description"
    
    // Metadata
    const detail = {
      judul_alternatif: null,
      judul_english: null,
      status: null,
      pengarang: [],
      ilustrator: [],
      jenis_komik: null,
      tema: [],
      tahun_rilis: null,
    }

    $(".spe span, .manga-detail .detail-content span").each((i, el) => {
      const text = $(el).text().trim()
      if (text.includes(':')) {
        const [key, ...valueParts] = text.split(':')
        const value = valueParts.join(':').trim()
        
        const keyLower = key.toLowerCase()
        if (keyLower.includes('alternatif')) detail.judul_alternatif = value
        else if (keyLower.includes('english')) detail.judul_english = value
        else if (keyLower.includes('status')) detail.status = value
        else if (keyLower.includes('pengarang') || keyLower.includes('author')) detail.pengarang = value.split(/,\s*/)
        else if (keyLower.includes('ilustrator') || keyLower.includes('artist')) detail.ilustrator = value.split(/,\s*/)
        else if (keyLower.includes('jenis') || keyLower.includes('type')) detail.jenis_komik = value
        else if (keyLower.includes('tema') || keyLower.includes('genre')) detail.tema = value.split(/,\s*/)
        else if (keyLower.includes('tahun') || keyLower.includes('year')) detail.tahun_rilis = parseInt(value) || null
      }
    })

    // Image
    const image = $(".thumb img, .summary_image img").attr("src") || ""

    // Rating
    const rating = {
      value: parseFloat($('span[itemprop="ratingValue"]').text().trim()) || 0,
      count: parseInt($('span[itemprop="ratingCount"]').text().trim()) || 0,
      best: 5
    }

    // Chapters
    const chapters = []
    if (includeChapters) {
      $(".listeps ul li, .chapter-list li, .wp-manga-chapter").each((i, el) => {
        try {
          const chapterTitle = $(el).find(".lchx a, a").text().trim() || "Chapter"
          const chapterLink = getPathFromUrl($(el).find("a").attr("href") || "")
          
          chapters.push({
            index: i + 1,
            judul_chapter: chapterTitle,
            slug: normalizeSlug(chapterTitle),
            link_chapter: chapterLink,
            chapter_number: extractChapterNumber(chapterTitle),
            waktu_rilis: $(el).find(".dt, .chapter-release-date").text().trim() || "",
          })
        } catch (error) {
          console.warn(`Error processing chapter ${i}:`, error.message)
        }
      })
    }

    // Sort chapters
    chapters.sort((a, b) => {
      if (a.chapter_number === null) return 1
      if (b.chapter_number === null) return -1
      return b.chapter_number - a.chapter_number
    })

    // Similar manga
    const similarManga = []
    if (includeSimilar) {
      $(".serieslist ul li, .related-manga .manga-item").each((i, el) => {
        try {
          const title = $(el).find("h4 a, .title a").text().trim() || "No Title"
          const link = getPathFromUrl($(el).find("a").attr("href") || "")
          const image = $(el).find("img").attr("src") || ""
          
          similarManga.push({
            judul: title,
            link: link,
            slug: normalizeSlug(title),
            gambar: image,
          })
        } catch (error) {
          console.warn(`Error processing similar manga ${i}:`, error.message)
        }
      })
    }

    // Genres
    const genre = []
    $(".genre-info a, .genres-content a").each((i, el) => {
      const name = $(el).text().trim()
      const link = getPathFromUrl($(el).attr("href") || "")
      
      genre.push({
        id: i + 1,
        nama: name,
        slug: normalizeSlug(name),
        link: link,
      })
    })

    const response = {
      metadata: {
        id: komikId,
        source: config.ACTIVE_SOURCE,
        timestamp: new Date().toISOString(),
        url: url,
      },
      judul: title,
      slug: komikId,
      gambar: image,
      rating: rating,
      detail: detail,
      genre: genre,
      deskripsi: description,
      total_chapters: chapters.length,
      daftar_chapter: chapters,
      komik_serupa: similarManga,
    }

    await cache.set(cacheKey, response, config.CACHE_TTL.DETAIL)
    return response
    
  } catch (error) {
    console.error('Error in getUltraKomikDetail:', error)
    throw error
  }
}

async function getUltimateKomikChapter(chapterId) {
  const cacheKey = cache.generateKey('chapter', chapterId)
  const cached = await cache.get(cacheKey, config.CACHE_TTL.CHAPTER)
  
  if (cached) {
    return cached
  }

  try {
    const url = `${config.TARGETS[config.ACTIVE_SOURCE]}/${chapterId}`
    const htmlContent = await scraper.fetchWithFallback(url)
    const $ = cheerio.load(htmlContent)

    const results = {
      metadata: {
        source: config.ACTIVE_SOURCE,
        url: url,
        timestamp: new Date().toISOString(),
      },
      judul: $(".entry-title").text().trim() || "No Title",
      slug: chapterId,
    }

    // Navigation
    results.navigasi = {
      sebelumnya: {
        text: $('a[rel="prev"]').text().trim() || "Previous",
        link: getPathFromUrl($('a[rel="prev"]').attr("href") || "")
      },
      selanjutnya: {
        text: $('a[rel="next"]').text().trim() || "Next",
        link: getPathFromUrl($('a[rel="next"]').attr("href") || "")
      },
    }

    // Images
    results.gambar = []
    $(".chapter-image img, #readerarea img, .wp-manga-chapter-img, .read-container img").each((index, el) => {
      const imgSrc = $(el).attr("src") || $(el).attr("data-src") || $(el).attr("data-lazy-src")
      if (imgSrc) {
        results.gambar.push({
          id: index + 1,
          url: imgSrc.split('?')[0],
          alt: $(el).attr("alt") || `Page ${index + 1}`,
        })
      }
    })

    // Chapter info
    results.chapter_metadata = {
      chapter_number: extractChapterNumber(results.judul),
      total_pages: results.gambar.length,
    }

    await cache.set(cacheKey, results, config.CACHE_TTL.CHAPTER)
    return results
    
  } catch (error) {
    console.error('Error in getUltimateKomikChapter:', error)
    throw error
  }
}

async function getTrendingKomik(period = 'daily', limit = 20) {
  const cacheKey = cache.generateKey('trending', `${period}-${limit}`)
  const cached = await cache.get(cacheKey, config.CACHE_TTL.TRENDING)
  
  if (cached) {
    return cached
  }

  try {
    // Different sources have different trending pages
    let url = ''
    switch(config.ACTIVE_SOURCE) {
      case 'KOMIKINDO':
        url = `${config.TARGETS[config.ACTIVE_SOURCE]}/trending/`
        break
      case 'KOMIKU':
        url = `${config.TARGETS[config.ACTIVE_SOURCE]}/trending/`
        break
      default:
        url = `${config.TARGETS[config.ACTIVE_SOURCE]}/`
    }

    const htmlContent = await scraper.fetchWithFallback(url)
    const $ = cheerio.load(htmlContent)

    const trending = []
    $('.trending-item, .popular-item, .serieslist.pop li').each((i, el) => {
      if (trending.length >= limit) return false
      
      const title = $(el).find('.title, h4 a').text().trim()
      const link = $(el).find('a').attr('href')
      const image = $(el).find('img').attr('src')
      const rank = $(el).find('.rank, .ctr').text().trim() || (i + 1)
      
      if (title && link) {
        trending.push({
          rank: parseInt(rank) || i + 1,
          title,
          slug: normalizeSlug(title),
          url: getPathFromUrl(link),
          image: image || '',
        })
      }
    })

    const response = {
      period,
      limit,
      total: trending.length,
      trending: trending.slice(0, limit)
    }

    await cache.set(cacheKey, response, config.CACHE_TTL.TRENDING)
    return response
    
  } catch (error) {
    console.error('Error in getTrendingKomik:', error)
    return {
      period,
      limit,
      total: 0,
      trending: [],
      error: error.message
    }
  }
}

// ==================== EXPRESS APP ====================
const app = express()

// CORS configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  maxAge: 86400
}))

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: {
    status: false,
    message: "Terlalu banyak permintaan. Coba lagi nanti.",
    data: null
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.path === '/health' || req.path === '/'
  }
})

app.use(limiter)

// Middleware
app.use(express.json({ limit: "10mb" }))
app.use(express.urlencoded({ extended: true, limit: "10mb" }))

// Security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff")
  res.setHeader("X-Frame-Options", "DENY")
  res.setHeader("X-XSS-Protection", "1; mode=block")
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin")
  res.setHeader("X-Powered-By", "CuymangaAPI/2.1.0")
  next()
})

// ==================== ROUTES ====================

// Health check
app.get("/health", async (req, res) => {
  const health = {
    status: "OK",
    version: "2.1.0",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: {
      rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
      heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
      heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
    },
    cache: {
      memory_size: scraper.memoryCache ? scraper.memoryCache.size : 0,
      redis: cache.redis ? "connected" : "disconnected"
    },
    sources: Object.entries(scraper.sourceStatus).map(([source, stats]) => ({
      source,
      ...stats,
      avgTime: stats.totalTime > 0 ? `${(stats.totalTime / (stats.successes + stats.failures)).toFixed(2)}ms` : "0ms"
    })),
    environment: {
      node: process.version,
      platform: process.platform,
      env: process.env.NODE_ENV || 'development'
    }
  }
  
  res.json(health)
})

// Stats endpoint
app.get("/stats", (req, res) => {
  res.json(monitor.getStats())
})

// Cache management (protected)
app.delete("/cache", async (req, res) => {
  const auth = req.headers.authorization
  if (process.env.ADMIN_TOKEN && (!auth || auth !== `Bearer ${process.env.ADMIN_TOKEN}`)) {
    return res.status(403).json({ 
      status: false, 
      message: "Unauthorized" 
    })
  }
  
  const pattern = req.query.pattern || '*'
  await cache.invalidate(pattern)
  
  res.json({ 
    status: true, 
    message: `Cache cleared for pattern: ${pattern}`,
    timestamp: new Date().toISOString()
  })
})

// Clear all cache
app.delete("/cache/all", async (req, res) => {
  const auth = req.headers.authorization
  if (process.env.ADMIN_TOKEN && (!auth || auth !== `Bearer ${process.env.ADMIN_TOKEN}`)) {
    return res.status(403).json({ 
      status: false, 
      message: "Unauthorized" 
    })
  }
  
  await cache.clearAll()
  
  res.json({ 
    status: true, 
    message: "All cache cleared",
    timestamp: new Date().toISOString()
  })
})

// Main API endpoint
app.get("/", async (req, res) => {
  const startTime = performance.now()
  const endpoint = Object.keys(req.query)[0] || 'home'
  
  try {
    // Route handling
    if (req.query.latest !== undefined) {
      const page = req.query.page ? parseInt(req.query.page) : 1
      const filter = {
        type: req.query.type || null,
        minRating: req.query.min_rating ? parseFloat(req.query.min_rating) : null
      }
      const data = await getEnhancedLatestKomik(page, filter)
      monitor.recordRequest('latest', config.ACTIVE_SOURCE, performance.now() - startTime, data._cached)
      return sendSuccess(res, data, startTime)
      
    } else if (req.query.komik) {
      const includeChapters = req.query.chapters !== 'false'
      const includeSimilar = req.query.similar !== 'false'
      const data = await getUltraKomikDetail(req.query.komik, includeChapters, includeSimilar)
      monitor.recordRequest('detail', config.ACTIVE_SOURCE, performance.now() - startTime, data._cached)
      return sendSuccess(res, data, startTime)
      
    } else if (req.query.chapter) {
      const data = await getUltimateKomikChapter(req.query.chapter)
      monitor.recordRequest('chapter', config.ACTIVE_SOURCE, performance.now() - startTime, data._cached)
      return sendSuccess(res, data, startTime)
      
    } else if (req.query.search || req.query.s || req.query.q) {
      const query = req.query.search || req.query.s || req.query.q
      const page = req.query.page ? parseInt(req.query.page) : 1
      const type = req.query.type || null
      const genre = req.query.genre ? req.query.genre.split(',') : []
      const data = await superSearch(query, page, type, genre)
      monitor.recordRequest('search', config.ACTIVE_SOURCE, performance.now() - startTime, data._cached)
      return sendSuccess(res, data, startTime)
      
    } else if (req.query.trending) {
      const period = req.query.period || 'daily'
      const limit = req.query.limit ? parseInt(req.query.limit) : 20
      const data = await getTrendingKomik(period, limit)
      monitor.recordRequest('trending', config.ACTIVE_SOURCE, performance.now() - startTime, data._cached)
      return sendSuccess(res, data, startTime)
      
    } else {
      // Documentation
      const documentation = {
        name: "CuymangaAPI",
        version: "2.1.0",
        description: "Ultimate Manga Scraper API - Vercel Ready",
        author: "whyudacok",
        features: [
          "✅ Multi-source scraping dengan fallback otomatis",
          "✅ Advanced caching dengan Redis + Memory",
          "✅ Rate limiting 60 requests/minute",
          "✅ Stealth headers & proxy rotation",
          "✅ Performance monitoring & analytics",
          "✅ Trending & recommendation",
          "✅ Health monitoring dengan diagnostics",
          "✅ Cache management API",
          "✅ Vercel deployment ready"
        ],
        endpoints: [
          { method: "GET", path: "/?latest=1&page=1", description: "Komik terbaru" },
          { method: "GET", path: "/?komik=solo-leveling", description: "Detail komik" },
          { method: "GET", path: "/?chapter=solo-leveling-chapter-1", description: "Chapter komik" },
          { method: "GET", path: "/?search=naruto&page=1", description: "Pencarian komik" },
          { method: "GET", path: "/?trending=1&limit=10", description: "Trending komik" },
          { method: "GET", path: "/health", description: "Health check" },
          { method: "GET", path: "/stats", description: "Statistics" },
          { method: "DELETE", path: "/cache?pattern=search:*", description: "Clear cache (admin)" },
        ],
        examples: {
          curl: [
            "curl 'https://your-api.vercel.app/?latest=1'",
            "curl 'https://your-api.vercel.app/?komik=solo-leveling'",
            "curl 'https://your-api.vercel.app/?search=naruto'",
            "curl 'https://your-api.vercel.app/health'"
          ]
        },
        sources: Object.keys(config.TARGETS),
        active_source: config.ACTIVE_SOURCE,
        cache_ttl: config.CACHE_TTL,
      }
      
      return sendSuccess(res, { documentation }, startTime)
    }
    
  } catch (error) {
    console.error("API Error:", error.message)
    monitor.recordError(config.ACTIVE_SOURCE, endpoint)
    
    return sendError(res, error, startTime)
  }
})

// Helper functions
function sendSuccess(res, data, startTime) {
  const duration = performance.now() - startTime
  
  const response = {
    status: true,
    data: data,
    metadata: {
      duration: `${duration.toFixed(2)}ms`,
      timestamp: new Date().toISOString(),
      cache: data._cached ? 'HIT' : 'MISS',
      cache_source: data._source || 'none',
      version: "2.1.0"
    }
  }
  
  // Clean up internal properties
  delete data._cached
  delete data._source
  delete data._duration
  delete data._needsRefresh
  
  res.json(response)
}

function sendError(res, error, startTime) {
  const duration = performance.now() - startTime
  
  const errorResponse = {
    status: false,
    data: null,
    error: {
      message: error.message,
      type: error.constructor.name,
      duration: `${duration.toFixed(2)}ms`
    },
    timestamp: new Date().toISOString(),
    suggestions: [
      "Coba lagi dalam beberapa saat",
      "Periksa parameter yang dikirim",
      "Gunakan endpoint /health untuk status server"
    ]
  }
  
  if (process.env.NODE_ENV === 'development') {
    errorResponse.error.stack = error.stack
  }
  
  const statusCode = error.message.includes('not found') ? 404 : 500
  res.status(statusCode).json(errorResponse)
}

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    status: false,
    message: "Endpoint tidak ditemukan",
    available_endpoints: ["/", "/health", "/stats", "/?latest=1", "/?komik=slug", "/?chapter=slug", "/?search=query"]
  })
})

// Global error handler
app.use((err, req, res, next) => {
  console.error("Global error:", err)
  
  res.status(500).json({
    status: false,
    message: "Internal server error",
    error_id: crypto.randomUUID(),
    timestamp: new Date().toISOString()
  })
})

// ==================== STARTUP ====================
async function initialize() {
  console.log("🚀 Initializing CuymangaAPI v2.1.0...")
  console.log("=".repeat(50))
  console.log("🎯 Active source:", config.ACTIVE_SOURCE)
  console.log("📊 Monitoring: enabled")
  console.log("💾 Cache:", cache.redis ? "Redis + Memory" : "Memory only")
  console.log("🔒 Rate limiting: 60 requests/minute")
  console.log("🔄 Fallback sources:", config.FALLBACK_SOURCES.join(', '))
  console.log("🌐 Environment:", process.env.NODE_ENV || 'development')
  console.log("=".repeat(50))
  
  // Test source connectivity
  for (const [source, url] of Object.entries(config.TARGETS)) {
    if (source === config.ACTIVE_SOURCE || config.FALLBACK_SOURCES.includes(source)) {
      try {
        await axios.head(url, { timeout: 5000 })
        console.log(`✅ ${source}: ${url}`)
      } catch {
        console.log(`⚠️  ${source}: ${url} (unreachable)`)
      }
    }
  }
}

// Vercel handler
module.exports = app

// Start server if not in Vercel
if (require.main === module) {
  const PORT = process.env.PORT || 3000
  app.listen(PORT, async () => {
    await initialize()
    console.log(`\n🚀 Server running on port ${PORT}`)
    console.log(`📖 API: http://localhost:${PORT}/`)
    console.log(`❤️  Health: http://localhost:${PORT}/health`)
    console.log(`📊 Stats: http://localhost:${PORT}/stats`)
  })
}

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received. Shutting down gracefully...')
  if (cache.redis) {
    await cache.redis.quit()
  }
  process.exit(0)
})

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error)
})

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason)
})