/**
 * Business Scraper Sync Queueable
 * Handles asynchronous synchronization with external Business Scraper system
 */
public class BusinessScraperSyncQueueable implements Queueable, Database.AllowsCallouts {
    
    private List<Lead> leads;
    private String operation; // INSERT, UPDATE, DELETE
    private static final String EXTERNAL_ENDPOINT = 'callout:BusinessScraperAPI/api/crm/webhook';
    
    public BusinessScraperSyncQueueable(List<Lead> leads, String operation) {
        this.leads = leads;
        this.operation = operation;
    }
    
    public void execute(QueueableContext context) {
        System.debug('BusinessScraperSyncQueueable.execute: Processing ' + leads.size() + ' leads for operation: ' + operation);
        
        try {
            // Process leads in batches to respect callout limits
            Integer batchSize = 10;
            Integer totalBatches = (Integer) Math.ceil((Decimal) leads.size() / batchSize);
            
            for (Integer i = 0; i < totalBatches; i++) {
                Integer startIndex = i * batchSize;
                Integer endIndex = Math.min(startIndex + batchSize, leads.size());
                List<Lead> batchLeads = new List<Lead>();
                
                for (Integer j = startIndex; j < endIndex; j++) {
                    batchLeads.add(leads[j]);
                }
                
                syncLeadBatch(batchLeads);
                
                // Add delay between batches to respect rate limits
                if (i < totalBatches - 1) {
                    // Note: In a real implementation, you might want to chain queueable jobs
                    // for better rate limit handling
                }
            }
            
            System.debug('BusinessScraperSyncQueueable: Successfully processed all batches');
            
        } catch (Exception e) {
            System.debug('BusinessScraperSyncQueueable: Error processing leads: ' + e.getMessage());
            
            // Log error for monitoring
            logSyncError(e.getMessage(), leads.size());
        }
    }
    
    /**
     * Sync a batch of leads to external system
     */
    private void syncLeadBatch(List<Lead> batchLeads) {
        try {
            // Prepare webhook payload
            Map<String, Object> webhookPayload = new Map<String, Object>();
            webhookPayload.put('operation', operation);
            webhookPayload.put('objectType', 'Lead');
            webhookPayload.put('timestamp', Datetime.now().formatGmt('yyyy-MM-dd\'T\'HH:mm:ss\'Z\''));
            webhookPayload.put('records', serializeLeads(batchLeads));
            
            // Make HTTP callout
            HttpRequest request = new HttpRequest();
            request.setEndpoint(EXTERNAL_ENDPOINT + '?providerId=salesforce');
            request.setMethod('POST');
            request.setHeader('Content-Type', 'application/json');
            request.setHeader('X-Salesforce-Signature', generateSignature(JSON.serialize(webhookPayload)));
            request.setBody(JSON.serialize(webhookPayload));
            request.setTimeout(30000); // 30 seconds
            
            Http http = new Http();
            HttpResponse response = http.send(request);
            
            if (response.getStatusCode() == 200) {
                System.debug('BusinessScraperSyncQueueable: Successfully synced batch of ' + batchLeads.size() + ' leads');
                updateSyncStatus(batchLeads, 'Success');
            } else {
                System.debug('BusinessScraperSyncQueueable: Sync failed with status: ' + response.getStatusCode() + ', body: ' + response.getBody());
                updateSyncStatus(batchLeads, 'Failed: ' + response.getStatusCode());
            }
            
        } catch (Exception e) {
            System.debug('BusinessScraperSyncQueueable: Error syncing batch: ' + e.getMessage());
            updateSyncStatus(batchLeads, 'Error: ' + e.getMessage());
        }
    }
    
    /**
     * Serialize leads for external system
     */
    private List<Map<String, Object>> serializeLeads(List<Lead> leadsToSerialize) {
        List<Map<String, Object>> serializedLeads = new List<Map<String, Object>>();
        
        for (Lead lead : leadsToSerialize) {
            Map<String, Object> leadData = new Map<String, Object>();
            leadData.put('id', lead.Id);
            leadData.put('businessName', lead.Company);
            leadData.put('email', new List<String>{ lead.Email });
            leadData.put('phone', lead.Phone);
            leadData.put('websiteUrl', lead.Website);
            leadData.put('contactPerson', lead.FirstName + ' ' + lead.LastName);
            leadData.put('industry', lead.Industry);
            leadData.put('status', lead.Status);
            leadData.put('rating', lead.Rating);
            leadData.put('leadSource', lead.LeadSource);
            leadData.put('scrapedAt', lead.CreatedDate?.formatGmt('yyyy-MM-dd\'T\'HH:mm:ss\'Z\''));
            
            // Address information
            Map<String, Object> address = new Map<String, Object>();
            address.put('street', lead.Street);
            address.put('city', lead.City);
            address.put('state', lead.State);
            address.put('zipCode', lead.PostalCode);
            leadData.put('address', address);
            
            // Custom fields
            if (lead.Priority__c != null) {
                leadData.put('priority', lead.Priority__c);
            }
            
            serializedLeads.add(leadData);
        }
        
        return serializedLeads;
    }
    
    /**
     * Generate signature for webhook authentication
     */
    private String generateSignature(String payload) {
        try {
            // Get the webhook secret from custom metadata or custom settings
            String webhookSecret = getWebhookSecret();
            
            if (String.isBlank(webhookSecret)) {
                return '';
            }
            
            // Generate HMAC-SHA256 signature
            Blob payloadBlob = Blob.valueOf(payload);
            Blob secretBlob = Blob.valueOf(webhookSecret);
            Blob signature = Crypto.generateMac('HmacSHA256', payloadBlob, secretBlob);
            
            return EncodingUtil.convertToHex(signature);
            
        } catch (Exception e) {
            System.debug('BusinessScraperSyncQueueable: Error generating signature: ' + e.getMessage());
            return '';
        }
    }
    
    /**
     * Get webhook secret from configuration
     */
    private String getWebhookSecret() {
        try {
            // Try to get from custom metadata first
            List<Business_Scraper_Config__mdt> configs = [
                SELECT Webhook_Secret__c 
                FROM Business_Scraper_Config__mdt 
                WHERE DeveloperName = 'Default' 
                LIMIT 1
            ];
            
            if (!configs.isEmpty() && !String.isBlank(configs[0].Webhook_Secret__c)) {
                return configs[0].Webhook_Secret__c;
            }
            
            // Fallback to custom setting
            Business_Scraper_Settings__c settings = Business_Scraper_Settings__c.getOrgDefaults();
            if (settings != null && !String.isBlank(settings.Webhook_Secret__c)) {
                return settings.Webhook_Secret__c;
            }
            
        } catch (Exception e) {
            System.debug('BusinessScraperSyncQueueable: Error getting webhook secret: ' + e.getMessage());
        }
        
        return '';
    }
    
    /**
     * Update sync status on lead records
     */
    private void updateSyncStatus(List<Lead> leadsToUpdate, String status) {
        try {
            List<Lead> leadsForUpdate = new List<Lead>();
            
            for (Lead lead : leadsToUpdate) {
                Lead updateLead = new Lead(Id = lead.Id);
                updateLead.Last_Sync_Status__c = status;
                updateLead.Last_Sync_Date__c = Datetime.now();
                leadsForUpdate.add(updateLead);
            }
            
            if (!leadsForUpdate.isEmpty()) {
                update leadsForUpdate;
            }
            
        } catch (Exception e) {
            System.debug('BusinessScraperSyncQueueable: Error updating sync status: ' + e.getMessage());
        }
    }
    
    /**
     * Log sync errors for monitoring
     */
    private void logSyncError(String errorMessage, Integer recordCount) {
        try {
            // Create error log record
            Business_Scraper_Sync_Log__c logRecord = new Business_Scraper_Sync_Log__c();
            logRecord.Operation__c = operation;
            logRecord.Record_Count__c = recordCount;
            logRecord.Status__c = 'Error';
            logRecord.Error_Message__c = errorMessage.length() > 255 ? errorMessage.substring(0, 255) : errorMessage;
            logRecord.Sync_Date__c = Datetime.now();
            
            insert logRecord;
            
        } catch (Exception e) {
            System.debug('BusinessScraperSyncQueueable: Error logging sync error: ' + e.getMessage());
        }
    }
}
