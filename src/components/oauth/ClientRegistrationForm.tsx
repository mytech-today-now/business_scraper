/**
 * OAuth Client Registration Form
 * Allows users to register new OAuth 2.0 clients
 */

'use client'

import React, { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Plus, X, AlertCircle, CheckCircle, Copy } from 'lucide-react'

interface ClientRegistrationFormProps {
  open: boolean
  onClose: () => void
  onClientRegistered?: (client: any) => void
}

interface FormData {
  clientName: string
  clientType: 'public' | 'confidential'
  redirectUris: string[]
  scopes: string[]
  grantTypes: string[]
  description: string
  logoUri: string
  clientUri: string
  contacts: string[]
}

const availableScopes = [
  { value: 'openid', label: 'OpenID Connect', description: 'Basic authentication' },
  { value: 'profile', label: 'Profile', description: 'Access to basic profile information' },
  { value: 'email', label: 'Email', description: 'Access to email address' },
  { value: 'read', label: 'Read', description: 'Read access to business data' },
  { value: 'write', label: 'Write', description: 'Write access to business data' },
  { value: 'admin', label: 'Admin', description: 'Administrative access' },
]

const availableGrantTypes = [
  { value: 'authorization_code', label: 'Authorization Code', description: 'Standard OAuth flow' },
  { value: 'refresh_token', label: 'Refresh Token', description: 'Token refresh capability' },
  { value: 'client_credentials', label: 'Client Credentials', description: 'Server-to-server authentication' },
]

export function ClientRegistrationForm({ 
  open, 
  onClose, 
  onClientRegistered 
}: ClientRegistrationFormProps): JSX.Element {
  const [formData, setFormData] = useState<FormData>({
    clientName: '',
    clientType: 'public',
    redirectUris: [''],
    scopes: ['openid', 'profile'],
    grantTypes: ['authorization_code', 'refresh_token'],
    description: '',
    logoUri: '',
    clientUri: '',
    contacts: [''],
  })

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [registrationResult, setRegistrationResult] = useState<any>(null)

  const handleInputChange = (field: keyof FormData, value: any): void => {
    setFormData(prev => ({ ...prev, [field]: value }))
    setError(null)
  }

  const handleArrayFieldChange = (field: 'redirectUris' | 'contacts', index: number, value: string): void => {
    setFormData(prev => ({
      ...prev,
      [field]: prev[field].map((item, i) => i === index ? value : item)
    }))
  }

  const addArrayField = (field: 'redirectUris' | 'contacts'): void => {
    setFormData(prev => ({
      ...prev,
      [field]: [...prev[field], '']
    }))
  }

  const removeArrayField = (field: 'redirectUris' | 'contacts', index: number): void => {
    setFormData(prev => ({
      ...prev,
      [field]: prev[field].filter((_, i) => i !== index)
    }))
  }

  const handleScopeToggle = (scope: string): void => {
    setFormData(prev => ({
      ...prev,
      scopes: prev.scopes.includes(scope)
        ? prev.scopes.filter(s => s !== scope)
        : [...prev.scopes, scope]
    }))
  }

  const handleGrantTypeToggle = (grantType: string): void => {
    setFormData(prev => ({
      ...prev,
      grantTypes: prev.grantTypes.includes(grantType)
        ? prev.grantTypes.filter(gt => gt !== grantType)
        : [...prev.grantTypes, grantType]
    }))
  }

  const validateForm = (): string | null => {
    if (!formData.clientName.trim()) {
      return 'Client name is required'
    }

    if (formData.redirectUris.filter(uri => uri.trim()).length === 0 && 
        !formData.grantTypes.includes('client_credentials')) {
      return 'At least one redirect URI is required for non-client-credentials flows'
    }

    if (formData.scopes.length === 0) {
      return 'At least one scope must be selected'
    }

    if (formData.grantTypes.length === 0) {
      return 'At least one grant type must be selected'
    }

    // Validate redirect URIs
    for (const uri of formData.redirectUris.filter(uri => uri.trim())) {
      try {
        new URL(uri)
      } catch {
        return `Invalid redirect URI: ${uri}`
      }
    }

    return null
  }

  const handleSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault()
    
    const validationError = validateForm()
    if (validationError) {
      setError(validationError)
      return
    }

    setLoading(true)
    setError(null)

    try {
      // In a real implementation, this would be an API call
      const registrationRequest = {
        client_name: formData.clientName,
        client_type: formData.clientType,
        redirect_uris: formData.redirectUris.filter(uri => uri.trim()),
        scope: formData.scopes.join(' '),
        grant_types: formData.grantTypes,
        contacts: formData.contacts.filter(contact => contact.trim()),
        logo_uri: formData.logoUri || undefined,
        client_uri: formData.clientUri || undefined,
      }

      // Mock registration response
      const mockResponse = {
        clientId: `client_${Date.now()}`,
        clientSecret: formData.clientType === 'confidential' ? `secret_${Date.now()}` : undefined,
        clientName: formData.clientName,
        clientType: formData.clientType,
        redirectUris: formData.redirectUris.filter(uri => uri.trim()),
        grantTypes: formData.grantTypes,
        scope: formData.scopes.join(' '),
        clientIdIssuedAt: Math.floor(Date.now() / 1000),
      }

      setRegistrationResult(mockResponse)
      onClientRegistered?.(mockResponse)

    } catch (error) {
      setError('Failed to register client. Please try again.')
      console.error('Client registration error:', error)
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = async (text: string): Promise<void> => {
    try {
      await navigator.clipboard.writeText(text)
    } catch (error) {
      console.error('Failed to copy to clipboard:', error)
    }
  }

  const resetForm = (): void => {
    setFormData({
      clientName: '',
      clientType: 'public',
      redirectUris: [''],
      scopes: ['openid', 'profile'],
      grantTypes: ['authorization_code', 'refresh_token'],
      description: '',
      logoUri: '',
      clientUri: '',
      contacts: [''],
    })
    setError(null)
    setRegistrationResult(null)
  }

  const handleClose = (): void => {
    resetForm()
    onClose()
  }

  if (registrationResult) {
    return (
      <Dialog open={open} onOpenChange={handleClose}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center">
              <CheckCircle className="h-5 w-5 text-green-500 mr-2" />
              Client Registered Successfully
            </DialogTitle>
            <DialogDescription>
              Your OAuth 2.0 client has been registered. Save these credentials securely.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <Alert>
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                <strong>Important:</strong> Save these credentials now. The client secret cannot be retrieved later.
              </AlertDescription>
            </Alert>

            <div className="space-y-3">
              <div>
                <Label className="text-sm font-medium">Client ID</Label>
                <div className="flex items-center space-x-2 mt-1">
                  <code className="flex-1 bg-muted px-3 py-2 rounded text-sm">
                    {registrationResult.clientId}
                  </code>
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => copyToClipboard(registrationResult.clientId)}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              {registrationResult.clientSecret && (
                <div>
                  <Label className="text-sm font-medium">Client Secret</Label>
                  <div className="flex items-center space-x-2 mt-1">
                    <code className="flex-1 bg-muted px-3 py-2 rounded text-sm">
                      {registrationResult.clientSecret}
                    </code>
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={() => copyToClipboard(registrationResult.clientSecret)}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}

              <div>
                <Label className="text-sm font-medium">Client Type</Label>
                <div className="mt-1">
                  <Badge variant={registrationResult.clientType === 'confidential' ? 'default' : 'secondary'}>
                    {registrationResult.clientType}
                  </Badge>
                </div>
              </div>

              <div>
                <Label className="text-sm font-medium">Allowed Scopes</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {registrationResult.scope.split(' ').map((scope: string) => (
                    <Badge key={scope} variant="outline" className="text-xs">
                      {scope}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex justify-end space-x-2 pt-4">
              <Button variant="outline" onClick={resetForm}>
                Register Another Client
              </Button>
              <Button onClick={handleClose}>
                Done
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    )
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Register OAuth 2.0 Client</DialogTitle>
          <DialogDescription>
            Create a new OAuth 2.0 client for your application
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-6">
          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {/* Basic Information */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium">Basic Information</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label htmlFor="clientName">Client Name *</Label>
                <Input
                  id="clientName"
                  value={formData.clientName}
                  onChange={(e) => handleInputChange('clientName', e.target.value)}
                  placeholder="My Application"
                  required
                />
              </div>

              <div>
                <Label htmlFor="clientType">Client Type *</Label>
                <Select 
                  value={formData.clientType} 
                  onValueChange={(value) => handleInputChange('clientType', value)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="public">Public (Mobile/SPA)</SelectItem>
                    <SelectItem value="confidential">Confidential (Server-side)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div>
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                value={formData.description}
                onChange={(e) => handleInputChange('description', e.target.value)}
                placeholder="Brief description of your application"
                rows={3}
              />
            </div>
          </div>

          {/* Redirect URIs */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium">Redirect URIs</h3>
            <p className="text-sm text-muted-foreground">
              URLs where users will be redirected after authorization
            </p>
            
            {formData.redirectUris.map((uri, index) => (
              <div key={index} className="flex items-center space-x-2">
                <Input
                  value={uri}
                  onChange={(e) => handleArrayFieldChange('redirectUris', index, e.target.value)}
                  placeholder="https://example.com/auth/callback"
                  className="flex-1"
                />
                {formData.redirectUris.length > 1 && (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => removeArrayField('redirectUris', index)}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                )}
              </div>
            ))}
            
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => addArrayField('redirectUris')}
            >
              <Plus className="h-4 w-4 mr-2" />
              Add Redirect URI
            </Button>
          </div>

          {/* Scopes */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium">Scopes</h3>
            <p className="text-sm text-muted-foreground">
              Permissions your application will request
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {availableScopes.map((scope) => (
                <div key={scope.value} className="flex items-start space-x-2">
                  <Checkbox
                    id={scope.value}
                    checked={formData.scopes.includes(scope.value)}
                    onCheckedChange={() => handleScopeToggle(scope.value)}
                  />
                  <div className="grid gap-1.5 leading-none">
                    <Label htmlFor={scope.value} className="text-sm font-medium">
                      {scope.label}
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      {scope.description}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Grant Types */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium">Grant Types</h3>
            <p className="text-sm text-muted-foreground">
              OAuth 2.0 flows your application will use
            </p>
            
            <div className="space-y-3">
              {availableGrantTypes.map((grantType) => (
                <div key={grantType.value} className="flex items-start space-x-2">
                  <Checkbox
                    id={grantType.value}
                    checked={formData.grantTypes.includes(grantType.value)}
                    onCheckedChange={() => handleGrantTypeToggle(grantType.value)}
                  />
                  <div className="grid gap-1.5 leading-none">
                    <Label htmlFor={grantType.value} className="text-sm font-medium">
                      {grantType.label}
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      {grantType.description}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Submit */}
          <div className="flex justify-end space-x-2 pt-4">
            <Button type="button" variant="outline" onClick={handleClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? 'Registering...' : 'Register Client'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
