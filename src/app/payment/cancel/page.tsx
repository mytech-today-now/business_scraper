/**
 * Payment Cancel Page
 * Displays when user cancels payment process
 */

'use client'

import React, { useEffect, Suspense } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { Button } from '@/view/components/ui/Button'
import { Card, CardHeader, CardTitle, CardContent } from '@/view/components/ui/Card'
import { XCircle, ArrowLeft, HelpCircle, MessageCircle } from 'lucide-react'
import { logger } from '@/utils/logger'

/**
 * Cancel Animation Component
 */
function CancelAnimation(): JSX.Element {
  return (
    <div className="flex items-center justify-center mb-6">
      <div className="relative">
        <div className="w-20 h-20 bg-orange-100 rounded-full flex items-center justify-center">
          <XCircle className="w-12 h-12 text-orange-600" />
        </div>
      </div>
    </div>
  )
}

/**
 * Reasons Component
 */
function CommonReasons(): JSX.Element {
  const reasons = [
    {
      title: 'Need more information?',
      description: 'Check out our detailed feature comparison and FAQ',
      action: 'View Features',
      href: '/features',
    },
    {
      title: 'Want to try before buying?',
      description: 'Start with our free trial to explore all features',
      action: 'Start Free Trial',
      href: '/trial',
    },
    {
      title: 'Have questions?',
      description: 'Our support team is here to help you choose the right plan',
      action: 'Contact Support',
      href: '/support',
    },
    {
      title: 'Looking for a different plan?',
      description: 'We have flexible options to fit your needs',
      action: 'View All Plans',
      href: '/pricing',
    },
  ]

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold text-center mb-6">How Can We Help?</h3>
      <div className="grid gap-4">
        {reasons.map((reason, index) => (
          <Card key={index} className="hover:shadow-md transition-shadow">
            <CardContent className="p-4">
              <div className="flex items-start gap-3">
                <div className="bg-primary/10 p-2 rounded-lg">
                  <HelpCircle className="w-5 h-5 text-primary" />
                </div>
                <div className="flex-1">
                  <h4 className="font-medium mb-1">{reason.title}</h4>
                  <p className="text-sm text-muted-foreground mb-3">{reason.description}</p>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => (window.location.href = reason.href)}
                    className="w-full sm:w-auto"
                  >
                    {reason.action}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

/**
 * Alternative Options Component
 */
function AlternativeOptions(): JSX.Element {
  const router = useRouter()

  return (
    <div className="grid md:grid-cols-2 gap-6">
      <Card className="bg-blue-50 border-blue-200">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <MessageCircle className="w-5 h-5" />
            Talk to Sales
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            Need a custom solution or have specific requirements? Our sales team can help you find
            the perfect plan.
          </p>
          <Button variant="outline" className="w-full">
            Schedule a Call
          </Button>
        </CardContent>
      </Card>

      <Card className="bg-green-50 border-green-200">
        <CardHeader>
          <CardTitle className="text-lg">Free Resources</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            Explore our free tools and resources to get started with business data collection.
          </p>
          <Button variant="outline" className="w-full">
            Browse Free Tools
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}

/**
 * Feedback Component
 */
function FeedbackSection(): JSX.Element {
  const [feedback, setFeedback] = React.useState('')
  const [isSubmitting, setIsSubmitting] = React.useState(false)

  const handleSubmitFeedback = async () => {
    if (!feedback.trim()) return

    try {
      setIsSubmitting(true)

      // TODO: Submit feedback to API
      logger.info('PaymentCancel', 'Feedback submitted', { feedback })

      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000))

      alert('Thank you for your feedback!')
      setFeedback('')
    } catch (error) {
      logger.error('PaymentCancel', 'Failed to submit feedback', error)
      alert('Failed to submit feedback. Please try again.')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Help Us Improve</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          We'd love to know what made you cancel. Your feedback helps us improve our service.
        </p>
        <textarea
          value={feedback}
          onChange={e => setFeedback(e.target.value)}
          placeholder="Tell us what we could do better..."
          className="w-full p-3 border rounded-md resize-none h-24"
          maxLength={500}
        />
        <div className="flex justify-between items-center">
          <span className="text-xs text-muted-foreground">{feedback.length}/500 characters</span>
          <Button
            onClick={handleSubmitFeedback}
            disabled={!feedback.trim() || isSubmitting}
            size="sm"
          >
            {isSubmitting ? 'Submitting...' : 'Submit Feedback'}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

/**
 * Payment Cancel Content Component (with search params)
 */
function PaymentCancelContent(): JSX.Element {
  const searchParams = useSearchParams()
  const router = useRouter()

  // Extract URL parameters
  const sessionId = searchParams.get('session_id')
  const reason = searchParams.get('reason')

  useEffect(() => {
    // Log payment cancellation
    logger.info('PaymentCancel', 'Payment cancel page loaded', {
      sessionId,
      reason,
    })
  }, [sessionId, reason])

  const handleReturnToPricing = () => {
    router.push('/pricing')
  }

  const handleGoHome = () => {
    router.push('/')
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="max-w-2xl w-full space-y-8">
        {/* Cancel Header */}
        <div className="text-center">
          <CancelAnimation />
          <h1 className="text-3xl font-bold mb-2">Payment Cancelled</h1>
          <p className="text-muted-foreground text-lg">
            No worries! Your payment was not processed and no charges were made.
          </p>
        </div>

        {/* Quick Actions */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Button onClick={handleReturnToPricing} size="lg" className="flex items-center gap-2">
            <ArrowLeft className="w-4 h-4" />
            Back to Pricing
          </Button>
          <Button onClick={handleGoHome} variant="outline" size="lg">
            Go to Homepage
          </Button>
        </div>

        {/* Common Reasons */}
        <CommonReasons />

        {/* Alternative Options */}
        <AlternativeOptions />

        {/* Feedback Section */}
        <FeedbackSection />

        {/* Contact Information */}
        <Card className="bg-gray-50 border-gray-200">
          <CardContent className="p-6 text-center">
            <h3 className="font-semibold mb-2">Still Have Questions?</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Our team is available 24/7 to help you find the right solution.
            </p>
            <div className="flex flex-col sm:flex-row gap-2 justify-center">
              <Button variant="outline" size="sm">
                Live Chat
              </Button>
              <Button variant="outline" size="sm">
                Email Support
              </Button>
              <Button variant="outline" size="sm">
                Call Us
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Footer */}
        <div className="text-center text-sm text-muted-foreground">
          <p>
            We're here to help you succeed. Don't hesitate to reach out if you need assistance
            choosing the right plan for your business.
          </p>
        </div>
      </div>
    </div>
  )
}

/**
 * Main Payment Cancel Page Component with Suspense
 */
export default function PaymentCancelPage(): JSX.Element {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-background flex items-center justify-center">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
            <p>Loading...</p>
          </div>
        </div>
      }
    >
      <PaymentCancelContent />
    </Suspense>
  )
}
