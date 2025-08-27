/**
 * Business Scraper Lead Trigger
 * Handles lead processing for business scraper integration
 */
trigger BusinessScraperLeadTrigger on Lead (before insert, after insert, before update, after update) {
    
    // Delegate to handler class for better maintainability
    BusinessScraperLeadTriggerHandler handler = new BusinessScraperLeadTriggerHandler();
    
    if (Trigger.isBefore) {
        if (Trigger.isInsert) {
            handler.beforeInsert(Trigger.new);
        } else if (Trigger.isUpdate) {
            handler.beforeUpdate(Trigger.new, Trigger.oldMap);
        }
    } else if (Trigger.isAfter) {
        if (Trigger.isInsert) {
            handler.afterInsert(Trigger.new);
        } else if (Trigger.isUpdate) {
            handler.afterUpdate(Trigger.new, Trigger.oldMap);
        }
    }
}
