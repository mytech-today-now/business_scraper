/**
 * Business Scraper Lead Trigger Handler
 * Handles business logic for lead processing from business scraper
 */
public class BusinessScraperLeadTriggerHandler {
    
    private static final String BUSINESS_SCRAPER_SOURCE = 'Business Scraper';
    private static final String DUPLICATE_REASON = 'Duplicate detected by Business Scraper';
    
    /**
     * Before Insert Handler
     * Validates and enriches lead data before insertion
     */
    public void beforeInsert(List<Lead> newLeads) {
        System.debug('BusinessScraperLeadTriggerHandler.beforeInsert: Processing ' + newLeads.size() + ' leads');
        
        // Validate required fields
        validateRequiredFields(newLeads);
        
        // Standardize data formats
        standardizeDataFormats(newLeads);
        
        // Check for duplicates
        preventDuplicateLeads(newLeads);
        
        // Enrich lead data
        enrichLeadData(newLeads);
    }
    
    /**
     * After Insert Handler
     * Performs post-insertion processing
     */
    public void afterInsert(List<Lead> newLeads) {
        System.debug('BusinessScraperLeadTriggerHandler.afterInsert: Processing ' + newLeads.size() + ' leads');
        
        // Send notifications for high-priority leads
        sendNotificationsForHighPriorityLeads(newLeads);
        
        // Create follow-up tasks
        createFollowUpTasks(newLeads);
        
        // Update external system (async)
        updateExternalSystemAsync(newLeads);
    }
    
    /**
     * Before Update Handler
     * Validates and processes lead updates
     */
    public void beforeUpdate(List<Lead> newLeads, Map<Id, Lead> oldLeadMap) {
        System.debug('BusinessScraperLeadTriggerHandler.beforeUpdate: Processing ' + newLeads.size() + ' leads');
        
        // Validate updates
        validateLeadUpdates(newLeads, oldLeadMap);
        
        // Track significant changes
        trackSignificantChanges(newLeads, oldLeadMap);
    }
    
    /**
     * After Update Handler
     * Performs post-update processing
     */
    public void afterUpdate(List<Lead> newLeads, Map<Id, Lead> oldLeadMap) {
        System.debug('BusinessScraperLeadTriggerHandler.afterUpdate: Processing ' + newLeads.size() + ' leads');
        
        // Sync changes back to external system
        syncChangesToExternalSystem(newLeads, oldLeadMap);
        
        // Update related records
        updateRelatedRecords(newLeads, oldLeadMap);
    }
    
    /**
     * Validate required fields for business scraper leads
     */
    private void validateRequiredFields(List<Lead> leads) {
        for (Lead lead : leads) {
            if (lead.LeadSource == BUSINESS_SCRAPER_SOURCE) {
                if (String.isBlank(lead.Company)) {
                    lead.addError('Company name is required for Business Scraper leads');
                }
                if (String.isBlank(lead.Email)) {
                    lead.addError('Email is required for Business Scraper leads');
                }
                if (String.isBlank(lead.Website)) {
                    lead.addError('Website is required for Business Scraper leads');
                }
            }
        }
    }
    
    /**
     * Standardize data formats (phone, email, website)
     */
    private void standardizeDataFormats(List<Lead> leads) {
        for (Lead lead : leads) {
            if (lead.LeadSource == BUSINESS_SCRAPER_SOURCE) {
                // Standardize phone format
                if (!String.isBlank(lead.Phone)) {
                    lead.Phone = standardizePhoneNumber(lead.Phone);
                }
                
                // Standardize email format
                if (!String.isBlank(lead.Email)) {
                    lead.Email = lead.Email.toLowerCase().trim();
                }
                
                // Standardize website format
                if (!String.isBlank(lead.Website)) {
                    lead.Website = standardizeWebsiteUrl(lead.Website);
                }
            }
        }
    }
    
    /**
     * Prevent duplicate leads based on email and company
     */
    private void preventDuplicateLeads(List<Lead> newLeads) {
        Set<String> emailSet = new Set<String>();
        Set<String> companySet = new Set<String>();
        
        // Collect emails and companies from new leads
        for (Lead lead : newLeads) {
            if (lead.LeadSource == BUSINESS_SCRAPER_SOURCE) {
                if (!String.isBlank(lead.Email)) {
                    emailSet.add(lead.Email.toLowerCase());
                }
                if (!String.isBlank(lead.Company)) {
                    companySet.add(lead.Company.toLowerCase());
                }
            }
        }
        
        // Query existing leads with same email or company
        List<Lead> existingLeads = [
            SELECT Id, Email, Company, Website
            FROM Lead
            WHERE (Email IN :emailSet OR Company IN :companySet)
            AND LeadSource = :BUSINESS_SCRAPER_SOURCE
            AND IsConverted = false
        ];
        
        // Create maps for quick lookup
        Map<String, Lead> emailToLeadMap = new Map<String, Lead>();
        Map<String, Lead> companyToLeadMap = new Map<String, Lead>();
        
        for (Lead existingLead : existingLeads) {
            if (!String.isBlank(existingLead.Email)) {
                emailToLeadMap.put(existingLead.Email.toLowerCase(), existingLead);
            }
            if (!String.isBlank(existingLead.Company)) {
                companyToLeadMap.put(existingLead.Company.toLowerCase(), existingLead);
            }
        }
        
        // Check for duplicates and prevent insertion
        for (Lead newLead : newLeads) {
            if (newLead.LeadSource == BUSINESS_SCRAPER_SOURCE) {
                String email = !String.isBlank(newLead.Email) ? newLead.Email.toLowerCase() : null;
                String company = !String.isBlank(newLead.Company) ? newLead.Company.toLowerCase() : null;
                
                Lead duplicateByEmail = email != null ? emailToLeadMap.get(email) : null;
                Lead duplicateByCompany = company != null ? companyToLeadMap.get(company) : null;
                
                if (duplicateByEmail != null) {
                    newLead.addError('Duplicate lead found with same email: ' + duplicateByEmail.Id);
                } else if (duplicateByCompany != null) {
                    newLead.addError('Duplicate lead found with same company: ' + duplicateByCompany.Id);
                }
            }
        }
    }
    
    /**
     * Enrich lead data with additional information
     */
    private void enrichLeadData(List<Lead> leads) {
        for (Lead lead : leads) {
            if (lead.LeadSource == BUSINESS_SCRAPER_SOURCE) {
                // Set default values
                if (String.isBlank(lead.Status)) {
                    lead.Status = 'New';
                }
                
                if (String.isBlank(lead.Rating)) {
                    lead.Rating = 'Warm';
                }
                
                // Set industry based on website domain or company name
                if (String.isBlank(lead.Industry)) {
                    lead.Industry = inferIndustryFromCompany(lead.Company, lead.Website);
                }
                
                // Set lead priority based on company size indicators
                lead.Priority__c = calculateLeadPriority(lead);
            }
        }
    }
    
    /**
     * Send notifications for high-priority leads
     */
    private void sendNotificationsForHighPriorityLeads(List<Lead> leads) {
        List<Lead> highPriorityLeads = new List<Lead>();
        
        for (Lead lead : leads) {
            if (lead.LeadSource == BUSINESS_SCRAPER_SOURCE && lead.Priority__c == 'High') {
                highPriorityLeads.add(lead);
            }
        }
        
        if (!highPriorityLeads.isEmpty()) {
            // Send email notifications (implement as needed)
            System.debug('Sending notifications for ' + highPriorityLeads.size() + ' high-priority leads');
        }
    }
    
    /**
     * Create follow-up tasks for new leads
     */
    private void createFollowUpTasks(List<Lead> leads) {
        List<Task> tasksToInsert = new List<Task>();
        
        for (Lead lead : leads) {
            if (lead.LeadSource == BUSINESS_SCRAPER_SOURCE) {
                Task followUpTask = new Task(
                    WhoId = lead.Id,
                    Subject = 'Follow up on Business Scraper lead: ' + lead.Company,
                    Description = 'Contact lead generated from Business Scraper application',
                    ActivityDate = Date.today().addDays(1),
                    Priority = 'Normal',
                    Status = 'Not Started'
                );
                tasksToInsert.add(followUpTask);
            }
        }
        
        if (!tasksToInsert.isEmpty()) {
            try {
                insert tasksToInsert;
                System.debug('Created ' + tasksToInsert.size() + ' follow-up tasks');
            } catch (Exception e) {
                System.debug('Error creating follow-up tasks: ' + e.getMessage());
            }
        }
    }
    
    /**
     * Update external system asynchronously
     */
    private void updateExternalSystemAsync(List<Lead> leads) {
        // Queue async job to update external system
        if (!leads.isEmpty()) {
            System.enqueueJob(new BusinessScraperSyncQueueable(leads, 'INSERT'));
        }
    }
    
    /**
     * Validate lead updates
     */
    private void validateLeadUpdates(List<Lead> newLeads, Map<Id, Lead> oldLeadMap) {
        for (Lead newLead : newLeads) {
            Lead oldLead = oldLeadMap.get(newLead.Id);
            
            if (newLead.LeadSource == BUSINESS_SCRAPER_SOURCE) {
                // Prevent changes to critical fields
                if (oldLead.Email != newLead.Email && !String.isBlank(oldLead.Email)) {
                    newLead.addError('Email cannot be changed for Business Scraper leads');
                }
                
                if (oldLead.Website != newLead.Website && !String.isBlank(oldLead.Website)) {
                    newLead.addError('Website cannot be changed for Business Scraper leads');
                }
            }
        }
    }
    
    /**
     * Track significant changes
     */
    private void trackSignificantChanges(List<Lead> newLeads, Map<Id, Lead> oldLeadMap) {
        for (Lead newLead : newLeads) {
            Lead oldLead = oldLeadMap.get(newLead.Id);
            
            if (newLead.LeadSource == BUSINESS_SCRAPER_SOURCE) {
                // Track status changes
                if (oldLead.Status != newLead.Status) {
                    System.debug('Lead status changed from ' + oldLead.Status + ' to ' + newLead.Status + ' for lead: ' + newLead.Id);
                }
            }
        }
    }
    
    /**
     * Sync changes back to external system
     */
    private void syncChangesToExternalSystem(List<Lead> newLeads, Map<Id, Lead> oldLeadMap) {
        List<Lead> leadsToSync = new List<Lead>();
        
        for (Lead newLead : newLeads) {
            if (newLead.LeadSource == BUSINESS_SCRAPER_SOURCE) {
                leadsToSync.add(newLead);
            }
        }
        
        if (!leadsToSync.isEmpty()) {
            System.enqueueJob(new BusinessScraperSyncQueueable(leadsToSync, 'UPDATE'));
        }
    }
    
    /**
     * Update related records
     */
    private void updateRelatedRecords(List<Lead> newLeads, Map<Id, Lead> oldLeadMap) {
        // Implementation for updating related records as needed
        System.debug('Updating related records for ' + newLeads.size() + ' leads');
    }
    
    // Helper methods
    private String standardizePhoneNumber(String phone) {
        if (String.isBlank(phone)) return phone;
        
        String cleanPhone = phone.replaceAll('[^0-9]', '');
        if (cleanPhone.length() == 10) {
            return '(' + cleanPhone.substring(0, 3) + ') ' + cleanPhone.substring(3, 6) + '-' + cleanPhone.substring(6);
        } else if (cleanPhone.length() == 11 && cleanPhone.startsWith('1')) {
            return '+1 (' + cleanPhone.substring(1, 4) + ') ' + cleanPhone.substring(4, 7) + '-' + cleanPhone.substring(7);
        }
        return phone;
    }
    
    private String standardizeWebsiteUrl(String website) {
        if (String.isBlank(website)) return website;
        
        website = website.trim().toLowerCase();
        if (!website.startsWith('http://') && !website.startsWith('https://')) {
            website = 'https://' + website;
        }
        return website;
    }
    
    private String inferIndustryFromCompany(String company, String website) {
        if (String.isBlank(company) && String.isBlank(website)) return 'Other';
        
        String searchText = (company + ' ' + website).toLowerCase();
        
        if (searchText.contains('tech') || searchText.contains('software') || searchText.contains('app')) {
            return 'Technology';
        } else if (searchText.contains('health') || searchText.contains('medical') || searchText.contains('pharma')) {
            return 'Healthcare';
        } else if (searchText.contains('finance') || searchText.contains('bank') || searchText.contains('invest')) {
            return 'Financial Services';
        } else if (searchText.contains('retail') || searchText.contains('store') || searchText.contains('shop')) {
            return 'Retail';
        } else if (searchText.contains('restaurant') || searchText.contains('food') || searchText.contains('cafe')) {
            return 'Food & Beverage';
        }
        
        return 'Other';
    }
    
    private String calculateLeadPriority(Lead lead) {
        Integer score = 0;
        
        // Score based on company name indicators
        if (!String.isBlank(lead.Company)) {
            String company = lead.Company.toLowerCase();
            if (company.contains('inc') || company.contains('corp') || company.contains('llc')) {
                score += 2;
            }
            if (company.contains('enterprise') || company.contains('solutions') || company.contains('group')) {
                score += 3;
            }
        }
        
        // Score based on website domain
        if (!String.isBlank(lead.Website)) {
            String website = lead.Website.toLowerCase();
            if (!website.contains('wordpress') && !website.contains('wix') && !website.contains('squarespace')) {
                score += 2;
            }
        }
        
        // Score based on industry
        if (!String.isBlank(lead.Industry)) {
            if (lead.Industry == 'Technology' || lead.Industry == 'Financial Services') {
                score += 3;
            }
        }
        
        if (score >= 6) {
            return 'High';
        } else if (score >= 3) {
            return 'Medium';
        } else {
            return 'Low';
        }
    }
}
