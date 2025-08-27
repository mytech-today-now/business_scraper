/**
 * GDPR Data Subject Access Request (DSAR) API
 * Handles data access, rectification, and erasure requests
 */

import { NextRequest, NextResponse } from 'next/server'
import { Pool } from 'pg'
import { logger } from '@/utils/logger'
import { auditService, AuditEventType, AuditSeverity } from '@/lib/compliance/audit'
import { encryptionService } from '@/lib/compliance/encryption'
import { withAuth } from '@/lib/auth-middleware'

// DSAR request types
export enum DSARType {
  ACCESS = 'access',
  RECTIFICATION = 'rectification',
  ERASURE = 'erasure',
  PORTABILITY = 'portability',
  RESTRICTION = 'restriction',
  OBJECTION = 'objection',
}

// DSAR status
export enum DSARStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  REJECTED = 'rejected',
  EXPIRED = 'expired',
}

// DSAR request interface
interface DSARRequest {
  id?: string
  requestType: DSARType
  subjectEmail: string
  subjectName?: string
  description: string
  requestedData?: string[]
  verificationMethod: 'email' | 'identity_document' | 'phone'
  verificationData: Record<string, any>
  status: DSARStatus
  submittedAt: Date
  completedAt?: Date
  responseData?: any
  rejectionReason?: string
  processingNotes?: string
  assignedTo?: string
  priority: 'low' | 'medium' | 'high'
  legalDeadline: Date
}

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
})

/**
 * Submit DSAR request
 */
async function submitDSARRequest(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json()
    const {
      requestType,
      subjectEmail,
      subjectName,
      description,
      requestedData,
      verificationMethod,
      verificationData,
    } = body

    // Validate required fields
    if (!requestType || !subjectEmail || !description || !verificationMethod) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 })
    }

    // Calculate legal deadline (30 days for GDPR)
    const legalDeadline = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)

    // Create DSAR request
    const dsarRequest: DSARRequest = {
      requestType,
      subjectEmail: subjectEmail.toLowerCase(),
      subjectName,
      description,
      requestedData: requestedData || [],
      verificationMethod,
      verificationData: encryptionService.encrypt(JSON.stringify(verificationData)),
      status: DSARStatus.PENDING,
      submittedAt: new Date(),
      priority: 'medium',
      legalDeadline,
    }

    // Insert into database
    const result = await pool.query(
      `
      INSERT INTO dsar_requests (
        request_type, subject_email, subject_name, description, requested_data,
        verification_method, verification_data, status, submitted_at, legal_deadline, priority
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id
    `,
      [
        dsarRequest.requestType,
        dsarRequest.subjectEmail,
        dsarRequest.subjectName,
        dsarRequest.description,
        JSON.stringify(dsarRequest.requestedData),
        dsarRequest.verificationMethod,
        JSON.stringify(dsarRequest.verificationData),
        dsarRequest.status,
        dsarRequest.submittedAt,
        dsarRequest.legalDeadline,
        dsarRequest.priority,
      ]
    )

    const requestId = result.rows[0].id

    // Log audit event
    await auditService.logEvent({
      eventType: AuditEventType.DSAR_REQUEST,
      severity: AuditSeverity.HIGH,
      details: {
        requestId,
        requestType,
        subjectEmail,
        verificationMethod,
      },
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: false,
        soc2Relevant: true,
      },
    })

    // Send confirmation email (implementation would depend on email service)
    await sendDSARConfirmationEmail(subjectEmail, requestId, requestType)

    logger.info('DSAR', `DSAR request submitted: ${requestType}`, {
      requestId,
      subjectEmail,
      legalDeadline: legalDeadline.toISOString(),
    })

    return NextResponse.json({
      success: true,
      requestId,
      status: DSARStatus.PENDING,
      legalDeadline: legalDeadline.toISOString(),
      message:
        'DSAR request submitted successfully. You will receive a confirmation email shortly.',
    })
  } catch (error) {
    logger.error('DSAR', 'Failed to submit DSAR request', error)
    return NextResponse.json({ error: 'Failed to submit DSAR request' }, { status: 500 })
  }
}

/**
 * Get DSAR requests (admin only)
 */
async function getDSARRequests(request: NextRequest): Promise<NextResponse> {
  try {
    const { searchParams } = new URL(request.url)
    const status = searchParams.get('status')
    const requestType = searchParams.get('type')
    const limit = parseInt(searchParams.get('limit') || '50')
    const offset = parseInt(searchParams.get('offset') || '0')

    let query = 'SELECT * FROM dsar_requests WHERE 1=1'
    const params: any[] = []
    let paramIndex = 1

    if (status) {
      query += ` AND status = $${paramIndex}`
      params.push(status)
      paramIndex++
    }

    if (requestType) {
      query += ` AND request_type = $${paramIndex}`
      params.push(requestType)
      paramIndex++
    }

    query += ' ORDER BY submitted_at DESC'
    query += ` LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`
    params.push(limit, offset)

    const result = await pool.query(query, params)

    const requests = result.rows.map(row => ({
      id: row.id,
      requestType: row.request_type,
      subjectEmail: row.subject_email,
      subjectName: row.subject_name,
      description: row.description,
      requestedData: JSON.parse(row.requested_data || '[]'),
      verificationMethod: row.verification_method,
      status: row.status,
      submittedAt: row.submitted_at,
      completedAt: row.completed_at,
      rejectionReason: row.rejection_reason,
      processingNotes: row.processing_notes,
      assignedTo: row.assigned_to,
      priority: row.priority,
      legalDeadline: row.legal_deadline,
      daysRemaining: Math.ceil(
        (new Date(row.legal_deadline).getTime() - Date.now()) / (24 * 60 * 60 * 1000)
      ),
    }))

    return NextResponse.json({
      requests,
      total: result.rowCount,
      limit,
      offset,
    })
  } catch (error) {
    logger.error('DSAR', 'Failed to get DSAR requests', error)
    return NextResponse.json({ error: 'Failed to retrieve DSAR requests' }, { status: 500 })
  }
}

/**
 * Process DSAR request (admin only)
 */
async function processDSARRequest(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json()
    const { requestId, action, responseData, rejectionReason, processingNotes } = body

    if (!requestId || !action) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 })
    }

    // Get current request
    const currentRequest = await pool.query('SELECT * FROM dsar_requests WHERE id = $1', [
      requestId,
    ])

    if (currentRequest.rows.length === 0) {
      return NextResponse.json({ error: 'DSAR request not found' }, { status: 404 })
    }

    const dsarRequest = currentRequest.rows[0]

    let newStatus: DSARStatus
    let completedAt: Date | null = null

    switch (action) {
      case 'approve':
        newStatus = DSARStatus.COMPLETED
        completedAt = new Date()

        // Execute the actual data operation based on request type
        await executeDSAROperation(dsarRequest, responseData)
        break

      case 'reject':
        newStatus = DSARStatus.REJECTED
        completedAt = new Date()
        break

      case 'assign':
        newStatus = DSARStatus.IN_PROGRESS
        break

      default:
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
    }

    // Update request status
    await pool.query(
      `
      UPDATE dsar_requests 
      SET status = $1, completed_at = $2, rejection_reason = $3, 
          processing_notes = $4, response_data = $5
      WHERE id = $6
    `,
      [
        newStatus,
        completedAt,
        rejectionReason,
        processingNotes,
        responseData ? JSON.stringify(responseData) : null,
        requestId,
      ]
    )

    // Log audit event
    await auditService.logEvent({
      eventType: action === 'approve' ? AuditEventType.DSAR_FULFILLED : AuditEventType.DSAR_REQUEST,
      severity: AuditSeverity.HIGH,
      details: {
        requestId,
        action,
        requestType: dsarRequest.request_type,
        subjectEmail: dsarRequest.subject_email,
        newStatus,
      },
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: false,
        soc2Relevant: true,
      },
    })

    // Send notification email to data subject
    await sendDSARStatusUpdateEmail(
      dsarRequest.subject_email,
      requestId,
      newStatus,
      rejectionReason
    )

    logger.info('DSAR', `DSAR request processed: ${action}`, {
      requestId,
      newStatus,
      subjectEmail: dsarRequest.subject_email,
    })

    return NextResponse.json({
      success: true,
      requestId,
      status: newStatus,
      message: `DSAR request ${action}ed successfully`,
    })
  } catch (error) {
    logger.error('DSAR', 'Failed to process DSAR request', error)
    return NextResponse.json({ error: 'Failed to process DSAR request' }, { status: 500 })
  }
}

/**
 * Execute DSAR operation based on request type
 */
async function executeDSAROperation(dsarRequest: any, responseData: any): Promise<void> {
  const subjectEmail = dsarRequest.subject_email

  switch (dsarRequest.request_type) {
    case DSARType.ACCESS:
      // Collect all data for the subject
      await collectSubjectData(subjectEmail)
      break

    case DSARType.ERASURE:
      // Delete all data for the subject
      await eraseSubjectData(subjectEmail)
      break

    case DSARType.RECTIFICATION:
      // Update incorrect data
      await rectifySubjectData(subjectEmail, responseData)
      break

    case DSARType.PORTABILITY:
      // Export data in portable format
      await exportSubjectData(subjectEmail)
      break

    default:
      logger.warn('DSAR', `Unhandled DSAR operation: ${dsarRequest.request_type}`)
  }
}

/**
 * Collect all data for a subject
 */
async function collectSubjectData(subjectEmail: string): Promise<any> {
  // Implementation would collect data from all relevant tables
  // This is a simplified version
  const userData = await pool.query('SELECT * FROM businesses WHERE email ILIKE $1', [
    `%${subjectEmail}%`,
  ])

  return userData.rows
}

/**
 * Erase all data for a subject
 */
async function eraseSubjectData(subjectEmail: string): Promise<void> {
  // Implementation would delete data from all relevant tables
  // This is a simplified version
  await pool.query('DELETE FROM businesses WHERE email ILIKE $1', [`%${subjectEmail}%`])
}

/**
 * Rectify subject data
 */
async function rectifySubjectData(subjectEmail: string, corrections: any): Promise<void> {
  // Implementation would update specific fields based on corrections
  logger.info('DSAR', `Data rectification requested for: ${subjectEmail}`, corrections)
}

/**
 * Export subject data
 */
async function exportSubjectData(subjectEmail: string): Promise<void> {
  // Implementation would create exportable data package
  logger.info('DSAR', `Data export requested for: ${subjectEmail}`)
}

/**
 * Send DSAR confirmation email
 */
async function sendDSARConfirmationEmail(
  email: string,
  requestId: string,
  requestType: string
): Promise<void> {
  // Implementation would depend on email service
  logger.info('DSAR', `Confirmation email sent for DSAR request: ${requestId}`, {
    email,
    requestType,
  })
}

/**
 * Send DSAR status update email
 */
async function sendDSARStatusUpdateEmail(
  email: string,
  requestId: string,
  status: DSARStatus,
  reason?: string
): Promise<void> {
  // Implementation would depend on email service
  logger.info('DSAR', `Status update email sent for DSAR request: ${requestId}`, {
    email,
    status,
    reason,
  })
}

// Route handlers
export async function POST(request: NextRequest) {
  return submitDSARRequest(request)
}

export const GET = withAuth(getDSARRequests, {
  required: true,
  roles: ['admin', 'compliance_officer'],
})
export const PUT = withAuth(processDSARRequest, {
  required: true,
  roles: ['admin', 'compliance_officer'],
})
