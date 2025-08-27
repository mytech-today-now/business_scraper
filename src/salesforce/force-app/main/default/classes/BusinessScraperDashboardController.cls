/**
 * Business Scraper Dashboard Controller
 * Apex controller for Business Scraper Dashboard LWC
 */
public with sharing class BusinessScraperDashboardController {
    
    private static final String BUSINESS_SCRAPER_SOURCE = 'Business Scraper';
    
    /**
     * Get Business Scraper statistics
     */
    @AuraEnabled(cacheable=true)
    public static Map<String, Object> getBusinessScraperStats() {
        try {
            Map<String, Object> stats = new Map<String, Object>();
            
            // Get today's leads
            Integer totalLeadsToday = [
                SELECT COUNT() 
                FROM Lead 
                WHERE LeadSource = :BUSINESS_SCRAPER_SOURCE 
                AND CreatedDate = TODAY
            ];
            
            // Get this week's leads
            Integer totalLeadsThisWeek = [
                SELECT COUNT() 
                FROM Lead 
                WHERE LeadSource = :BUSINESS_SCRAPER_SOURCE 
                AND CreatedDate = THIS_WEEK
            ];
            
            // Get this month's leads
            Integer totalLeadsThisMonth = [
                SELECT COUNT() 
                FROM Lead 
                WHERE LeadSource = :BUSINESS_SCRAPER_SOURCE 
                AND CreatedDate = THIS_MONTH
            ];
            
            // Calculate conversion rate
            Integer totalLeads = [
                SELECT COUNT() 
                FROM Lead 
                WHERE LeadSource = :BUSINESS_SCRAPER_SOURCE 
                AND CreatedDate = THIS_MONTH
            ];
            
            Integer convertedLeads = [
                SELECT COUNT() 
                FROM Lead 
                WHERE LeadSource = :BUSINESS_SCRAPER_SOURCE 
                AND IsConverted = true 
                AND CreatedDate = THIS_MONTH
            ];
            
            Decimal conversionRate = totalLeads > 0 ? (Decimal.valueOf(convertedLeads) / Decimal.valueOf(totalLeads)) * 100 : 0;
            
            // Get last sync information
            Map<String, Object> syncInfo = getLastSyncInfo();
            
            stats.put('totalLeadsToday', totalLeadsToday);
            stats.put('totalLeadsThisWeek', totalLeadsThisWeek);
            stats.put('totalLeadsThisMonth', totalLeadsThisMonth);
            stats.put('conversionRate', conversionRate.setScale(1) + '%');
            stats.put('lastSyncTime', syncInfo.get('lastSyncTime'));
            stats.put('syncStatus', syncInfo.get('syncStatus'));
            
            return stats;
            
        } catch (Exception e) {
            System.debug('BusinessScraperDashboardController.getBusinessScraperStats: ' + e.getMessage());
            throw new AuraHandledException('Error retrieving Business Scraper statistics: ' + e.getMessage());
        }
    }
    
    /**
     * Get recent leads from Business Scraper
     */
    @AuraEnabled(cacheable=true)
    public static List<Lead> getRecentLeads(Integer limitCount) {
        try {
            if (limitCount == null || limitCount <= 0) {
                limitCount = 10;
            }
            
            List<Lead> recentLeads = [
                SELECT Id, Name, FirstName, LastName, Company, Email, Phone, Website, 
                       Status, Rating, Industry, Priority__c, CreatedDate, LastModifiedDate,
                       Last_Sync_Status__c, Last_Sync_Date__c
                FROM Lead 
                WHERE LeadSource = :BUSINESS_SCRAPER_SOURCE 
                ORDER BY CreatedDate DESC 
                LIMIT :limitCount
            ];
            
            return recentLeads;
            
        } catch (Exception e) {
            System.debug('BusinessScraperDashboardController.getRecentLeads: ' + e.getMessage());
            throw new AuraHandledException('Error retrieving recent leads: ' + e.getMessage());
        }
    }
    
    /**
     * Sync with external Business Scraper system
     */
    @AuraEnabled
    public static Map<String, Object> syncWithExternalSystem() {
        try {
            Map<String, Object> result = new Map<String, Object>();
            
            // Get leads that need to be synced (created or modified in last 24 hours)
            DateTime last24Hours = DateTime.now().addHours(-24);
            
            List<Lead> leadsToSync = [
                SELECT Id, Name, FirstName, LastName, Company, Email, Phone, Website, 
                       Status, Rating, Industry, Priority__c, CreatedDate, LastModifiedDate,
                       Last_Sync_Status__c, Last_Sync_Date__c
                FROM Lead 
                WHERE LeadSource = :BUSINESS_SCRAPER_SOURCE 
                AND (CreatedDate >= :last24Hours OR LastModifiedDate >= :last24Hours)
                AND (Last_Sync_Date__c = null OR Last_Sync_Date__c < LastModifiedDate)
                ORDER BY LastModifiedDate DESC
                LIMIT 100
            ];
            
            if (leadsToSync.isEmpty()) {
                result.put('success', true);
                result.put('message', 'No leads require synchronization');
                result.put('syncedCount', 0);
                return result;
            }
            
            // Queue async job for synchronization
            System.enqueueJob(new BusinessScraperSyncQueueable(leadsToSync, 'SYNC'));
            
            // Log sync initiation
            logSyncInitiation(leadsToSync.size());
            
            result.put('success', true);
            result.put('message', 'Synchronization initiated for ' + leadsToSync.size() + ' leads');
            result.put('syncedCount', leadsToSync.size());
            
            return result;
            
        } catch (Exception e) {
            System.debug('BusinessScraperDashboardController.syncWithExternalSystem: ' + e.getMessage());
            
            Map<String, Object> result = new Map<String, Object>();
            result.put('success', false);
            result.put('message', 'Sync failed: ' + e.getMessage());
            result.put('syncedCount', 0);
            
            return result;
        }
    }
    
    /**
     * Get lead conversion metrics
     */
    @AuraEnabled(cacheable=true)
    public static Map<String, Object> getConversionMetrics() {
        try {
            Map<String, Object> metrics = new Map<String, Object>();
            
            // Get conversion data by status
            List<AggregateResult> statusCounts = [
                SELECT Status, COUNT(Id) leadCount
                FROM Lead 
                WHERE LeadSource = :BUSINESS_SCRAPER_SOURCE 
                AND CreatedDate = THIS_MONTH
                GROUP BY Status
            ];
            
            Map<String, Integer> statusMap = new Map<String, Integer>();
            Integer totalLeads = 0;
            
            for (AggregateResult ar : statusCounts) {
                String status = (String) ar.get('Status');
                Integer count = (Integer) ar.get('leadCount');
                statusMap.put(status, count);
                totalLeads += count;
            }
            
            // Get conversion data by priority
            List<AggregateResult> priorityCounts = [
                SELECT Priority__c, COUNT(Id) leadCount
                FROM Lead 
                WHERE LeadSource = :BUSINESS_SCRAPER_SOURCE 
                AND CreatedDate = THIS_MONTH
                AND Priority__c != null
                GROUP BY Priority__c
            ];
            
            Map<String, Integer> priorityMap = new Map<String, Integer>();
            
            for (AggregateResult ar : priorityCounts) {
                String priority = (String) ar.get('Priority__c');
                Integer count = (Integer) ar.get('leadCount');
                priorityMap.put(priority, count);
            }
            
            metrics.put('statusBreakdown', statusMap);
            metrics.put('priorityBreakdown', priorityMap);
            metrics.put('totalLeads', totalLeads);
            
            return metrics;
            
        } catch (Exception e) {
            System.debug('BusinessScraperDashboardController.getConversionMetrics: ' + e.getMessage());
            throw new AuraHandledException('Error retrieving conversion metrics: ' + e.getMessage());
        }
    }
    
    /**
     * Get sync history
     */
    @AuraEnabled(cacheable=true)
    public static List<Business_Scraper_Sync_Log__c> getSyncHistory(Integer limitCount) {
        try {
            if (limitCount == null || limitCount <= 0) {
                limitCount = 20;
            }
            
            List<Business_Scraper_Sync_Log__c> syncHistory = [
                SELECT Id, Operation__c, Record_Count__c, Status__c, Error_Message__c, 
                       Sync_Date__c, CreatedDate
                FROM Business_Scraper_Sync_Log__c 
                ORDER BY CreatedDate DESC 
                LIMIT :limitCount
            ];
            
            return syncHistory;
            
        } catch (Exception e) {
            System.debug('BusinessScraperDashboardController.getSyncHistory: ' + e.getMessage());
            throw new AuraHandledException('Error retrieving sync history: ' + e.getMessage());
        }
    }
    
    // Private helper methods
    
    /**
     * Get last sync information
     */
    private static Map<String, Object> getLastSyncInfo() {
        Map<String, Object> syncInfo = new Map<String, Object>();
        
        try {
            // Get the most recent sync log
            List<Business_Scraper_Sync_Log__c> recentSyncs = [
                SELECT Status__c, Sync_Date__c, Error_Message__c
                FROM Business_Scraper_Sync_Log__c 
                ORDER BY Sync_Date__c DESC 
                LIMIT 1
            ];
            
            if (!recentSyncs.isEmpty()) {
                Business_Scraper_Sync_Log__c lastSync = recentSyncs[0];
                syncInfo.put('lastSyncTime', lastSync.Sync_Date__c?.format('MMM dd, yyyy HH:mm'));
                syncInfo.put('syncStatus', lastSync.Status__c);
            } else {
                syncInfo.put('lastSyncTime', 'Never');
                syncInfo.put('syncStatus', 'Unknown');
            }
            
        } catch (Exception e) {
            System.debug('BusinessScraperDashboardController.getLastSyncInfo: ' + e.getMessage());
            syncInfo.put('lastSyncTime', 'Error');
            syncInfo.put('syncStatus', 'Error');
        }
        
        return syncInfo;
    }
    
    /**
     * Log sync initiation
     */
    private static void logSyncInitiation(Integer recordCount) {
        try {
            Business_Scraper_Sync_Log__c logRecord = new Business_Scraper_Sync_Log__c();
            logRecord.Operation__c = 'MANUAL_SYNC';
            logRecord.Record_Count__c = recordCount;
            logRecord.Status__c = 'In Progress';
            logRecord.Sync_Date__c = DateTime.now();
            
            insert logRecord;
            
        } catch (Exception e) {
            System.debug('BusinessScraperDashboardController.logSyncInitiation: ' + e.getMessage());
        }
    }
}
