import { NextRequest, NextResponse } from 'next/server'
import { scraperService } from '@/model/scraperService'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { action, ...params } = body

    switch (action) {
      case 'initialize':
        await scraperService.initialize()
        return NextResponse.json({ success: true })

      case 'search':
        const { query, zipCode, maxResults } = params
        const urls = await scraperService.searchForWebsites(query, zipCode, maxResults)
        // Ensure we always return an array, even if empty
        return NextResponse.json({ urls: urls || [] })

      case 'scrape':
        const { url, depth } = params
        const businesses = await scraperService.scrapeWebsite(url, depth)
        return NextResponse.json({ businesses })

      case 'cleanup':
        await scraperService.cleanup()
        return NextResponse.json({ success: true })

      default:
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
    }
  } catch (error) {
    console.error('Scraping API error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
