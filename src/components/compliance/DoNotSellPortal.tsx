/**
 * "Do Not Sell My Info" Opt-Out Portal
 * CCPA compliance component for California residents
 */

'use client'

import React, { useState, useEffect } from 'react'
import { Shield, CheckCircle, AlertCircle, Mail, Phone, MapPin, Calendar } from 'lucide-react'
import { logger } from '@/utils/logger'

interface OptOutFormData {
  email: string
  firstName: string
  lastName: string
  phone?: string
  address?: {
    street: string
    city: string
    state: string
    zipCode: string
  }
  verificationMethod: 'email' | 'phone'
  confirmResidency: boolean
  confirmIdentity: boolean
}

interface OptOutStatus {
  isOptedOut: boolean
  optOutDate?: string
  requestId?: string
}

export default function DoNotSellPortal() {
  const [step, setStep] = useState<'form' | 'verification' | 'success' | 'error'>('form')
  const [formData, setFormData] = useState<OptOutFormData>({
    email: '',
    firstName: '',
    lastName: '',
    phone: '',
    address: {
      street: '',
      city: '',
      state: 'CA',
      zipCode: '',
    },
    verificationMethod: 'email',
    confirmResidency: false,
    confirmIdentity: false,
  })
  const [optOutStatus, setOptOutStatus] = useState<OptOutStatus | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Check existing opt-out status on component mount
  useEffect(() => {
    checkOptOutStatus()
  }, [])

  const checkOptOutStatus = async () => {
    try {
      const response = await fetch('/api/compliance/ccpa/status')
      const data = await response.json()

      if (data.success && data.optOutStatus) {
        setOptOutStatus(data.optOutStatus)
      }
    } catch (error) {
      logger.error('Do Not Sell Portal', 'Failed to check opt-out status', error)
    }
  }

  const handleInputChange = (field: string, value: any) => {
    if (field.includes('.')) {
      const [parent, child] = field.split('.')
      setFormData(prev => ({
        ...prev,
        [parent]: {
          ...prev[parent as keyof OptOutFormData],
          [child]: value,
        },
      }))
    } else {
      setFormData(prev => ({
        ...prev,
        [field]: value,
      }))
    }
  }

  const validateForm = (): boolean => {
    if (!formData.email || !formData.firstName || !formData.lastName) {
      setError('Please fill in all required fields')
      return false
    }

    if (!formData.email.includes('@')) {
      setError('Please enter a valid email address')
      return false
    }

    if (!formData.confirmResidency) {
      setError('You must confirm that you are a California resident')
      return false
    }

    if (!formData.confirmIdentity) {
      setError('You must confirm your identity')
      return false
    }

    return true
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    if (!validateForm()) {
      return
    }

    setIsLoading(true)

    try {
      const response = await fetch('/api/compliance/ccpa/opt-out', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          consumerEmail: formData.email,
          consumerName: `${formData.firstName} ${formData.lastName}`,
          phone: formData.phone,
          address: formData.address,
          verificationMethod: formData.verificationMethod,
          requestDetails: {
            timestamp: new Date().toISOString(),
            method: 'web_portal',
            confirmations: {
              residency: formData.confirmResidency,
              identity: formData.confirmIdentity,
            },
          },
        }),
      })

      const data = await response.json()

      if (data.success) {
        setOptOutStatus({
          isOptedOut: true,
          optOutDate: new Date().toISOString(),
          requestId: data.requestId,
        })
        setStep('success')
      } else {
        setError(data.error || 'Failed to process opt-out request')
        setStep('error')
      }
    } catch (error) {
      logger.error('Do Not Sell Portal', 'Failed to submit opt-out request', error)
      setError('Failed to submit request. Please try again.')
      setStep('error')
    } finally {
      setIsLoading(false)
    }
  }

  // If user is already opted out, show status
  if (optOutStatus?.isOptedOut) {
    return (
      <div className="max-w-2xl mx-auto p-6 bg-white rounded-lg shadow-lg">
        <div className="text-center">
          <CheckCircle className="h-16 w-16 text-green-600 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-gray-900 mb-2">You're Already Opted Out</h2>
          <p className="text-gray-600 mb-6">
            You have successfully opted out of the sale of your personal information.
          </p>

          <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
            <div className="flex items-center justify-between text-sm">
              <span className="font-medium text-green-800">Opt-out Date:</span>
              <span className="text-green-700">
                {optOutStatus.optOutDate
                  ? new Date(optOutStatus.optOutDate).toLocaleDateString()
                  : 'Unknown'}
              </span>
            </div>
            {optOutStatus.requestId && (
              <div className="flex items-center justify-between text-sm mt-2">
                <span className="font-medium text-green-800">Request ID:</span>
                <span className="text-green-700 font-mono text-xs">{optOutStatus.requestId}</span>
              </div>
            )}
          </div>

          <div className="text-left bg-gray-50 rounded-lg p-4">
            <h3 className="font-semibold text-gray-900 mb-2">What this means:</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• We will not sell your personal information to third parties</li>
              <li>• This preference will be honored for future data collection</li>
              <li>• You can contact us if you have questions about your opt-out status</li>
              <li>• This opt-out applies to all personal information we have about you</li>
            </ul>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-2xl mx-auto p-6 bg-white rounded-lg shadow-lg">
      <div className="text-center mb-8">
        <Shield className="h-12 w-12 text-blue-600 mx-auto mb-4" />
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          Do Not Sell My Personal Information
        </h1>
        <p className="text-gray-600">
          California residents can opt out of the sale of their personal information under the CCPA
        </p>
      </div>

      {step === 'form' && (
        <form onSubmit={handleSubmit} className="space-y-6">
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-red-600 flex-shrink-0" />
              <span className="text-red-700">{error}</span>
            </div>
          )}

          {/* Personal Information */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-900">Personal Information</h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">First Name *</label>
                <input
                  type="text"
                  value={formData.firstName}
                  onChange={e => handleInputChange('firstName', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Last Name *</label>
                <input
                  type="text"
                  value={formData.lastName}
                  onChange={e => handleInputChange('lastName', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Email Address *
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="email"
                  value={formData.email}
                  onChange={e => handleInputChange('email', e.target.value)}
                  className="w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Phone Number (Optional)
              </label>
              <div className="relative">
                <Phone className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="tel"
                  value={formData.phone}
                  onChange={e => handleInputChange('phone', e.target.value)}
                  className="w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
          </div>

          {/* California Address */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-900">California Address (Optional)</h3>
            <p className="text-sm text-gray-600">
              Providing your California address helps us verify your residency status.
            </p>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Street Address</label>
              <div className="relative">
                <MapPin className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="text"
                  value={formData.address?.street}
                  onChange={e => handleInputChange('address.street', e.target.value)}
                  className="w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">City</label>
                <input
                  type="text"
                  value={formData.address?.city}
                  onChange={e => handleInputChange('address.city', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">State</label>
                <select
                  value={formData.address?.state}
                  onChange={e => handleInputChange('address.state', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="CA">California</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">ZIP Code</label>
                <input
                  type="text"
                  value={formData.address?.zipCode}
                  onChange={e => handleInputChange('address.zipCode', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
          </div>

          {/* Verification Method */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-900">Verification Method</h3>

            <div className="space-y-2">
              <label className="flex items-center">
                <input
                  type="radio"
                  value="email"
                  checked={formData.verificationMethod === 'email'}
                  onChange={e => handleInputChange('verificationMethod', e.target.value)}
                  className="mr-3"
                />
                <span>Email verification (recommended)</span>
              </label>

              <label className="flex items-center">
                <input
                  type="radio"
                  value="phone"
                  checked={formData.verificationMethod === 'phone'}
                  onChange={e => handleInputChange('verificationMethod', e.target.value)}
                  className="mr-3"
                />
                <span>Phone verification</span>
              </label>
            </div>
          </div>

          {/* Confirmations */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-900">Confirmations</h3>

            <div className="space-y-3">
              <label className="flex items-start">
                <input
                  type="checkbox"
                  checked={formData.confirmResidency}
                  onChange={e => handleInputChange('confirmResidency', e.target.checked)}
                  className="mr-3 mt-1"
                  required
                />
                <span className="text-sm">
                  I confirm that I am a California resident and this request relates to my personal
                  information.
                </span>
              </label>

              <label className="flex items-start">
                <input
                  type="checkbox"
                  checked={formData.confirmIdentity}
                  onChange={e => handleInputChange('confirmIdentity', e.target.checked)}
                  className="mr-3 mt-1"
                  required
                />
                <span className="text-sm">
                  I confirm that I am the person whose personal information is the subject of this
                  request, or I am authorized to make this request on their behalf.
                </span>
              </label>
            </div>
          </div>

          {/* Submit Button */}
          <div className="pt-6">
            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-blue-600 text-white py-3 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Processing Request...' : 'Submit Opt-Out Request'}
            </button>
          </div>

          {/* Information */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h4 className="font-semibold text-blue-900 mb-2">What happens next?</h4>
            <ul className="text-sm text-blue-800 space-y-1">
              <li>• We'll send a verification email to confirm your identity</li>
              <li>• Once verified, your opt-out preference will be processed immediately</li>
              <li>• You'll receive a confirmation email with your request details</li>
              <li>• This opt-out applies to future sales of your personal information</li>
            </ul>
          </div>
        </form>
      )}

      {step === 'success' && (
        <div className="text-center">
          <CheckCircle className="h-16 w-16 text-green-600 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Request Submitted Successfully</h2>
          <p className="text-gray-600 mb-6">
            Your opt-out request has been processed. You will not receive any discriminatory
            treatment for exercising your privacy rights.
          </p>

          <div className="bg-green-50 border border-green-200 rounded-lg p-4">
            <p className="text-sm text-green-800">
              A confirmation email has been sent to <strong>{formData.email}</strong>
            </p>
          </div>
        </div>
      )}

      {step === 'error' && (
        <div className="text-center">
          <AlertCircle className="h-16 w-16 text-red-600 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Request Failed</h2>
          <p className="text-gray-600 mb-6">
            {error || 'There was an error processing your request. Please try again.'}
          </p>

          <button
            onClick={() => {
              setStep('form')
              setError(null)
            }}
            className="bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700"
          >
            Try Again
          </button>
        </div>
      )}
    </div>
  )
}
