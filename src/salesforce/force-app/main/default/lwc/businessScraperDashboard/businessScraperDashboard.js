/**
 * Business Scraper Dashboard LWC
 * Displays real-time data from Business Scraper application
 */
import { LightningElement, track, wire } from 'lwc';
import { refreshApex } from '@salesforce/apex';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import getBusinessScraperStats from '@salesforce/apex/BusinessScraperDashboardController.getBusinessScraperStats';
import getRecentLeads from '@salesforce/apex/BusinessScraperDashboardController.getRecentLeads';
import syncWithExternalSystem from '@salesforce/apex/BusinessScraperDashboardController.syncWithExternalSystem';

export default class BusinessScraperDashboard extends LightningElement {
    @track stats = {};
    @track recentLeads = [];
    @track isLoading = false;
    @track error = null;
    
    // Wire methods to get data
    @wire(getBusinessScraperStats)
    wiredStats({ error, data }) {
        if (data) {
            this.stats = data;
            this.error = null;
        } else if (error) {
            this.error = error;
            this.stats = {};
        }
    }
    
    @wire(getRecentLeads, { limitCount: 10 })
    wiredRecentLeads({ error, data }) {
        if (data) {
            this.recentLeads = data;
            this.error = null;
        } else if (error) {
            this.error = error;
            this.recentLeads = [];
        }
    }
    
    // Getters for computed properties
    get hasStats() {
        return Object.keys(this.stats).length > 0;
    }
    
    get hasRecentLeads() {
        return this.recentLeads && this.recentLeads.length > 0;
    }
    
    get totalLeadsToday() {
        return this.stats.totalLeadsToday || 0;
    }
    
    get totalLeadsThisWeek() {
        return this.stats.totalLeadsThisWeek || 0;
    }
    
    get totalLeadsThisMonth() {
        return this.stats.totalLeadsThisMonth || 0;
    }
    
    get conversionRate() {
        return this.stats.conversionRate || '0%';
    }
    
    get lastSyncTime() {
        return this.stats.lastSyncTime || 'Never';
    }
    
    get syncStatus() {
        return this.stats.syncStatus || 'Unknown';
    }
    
    get syncStatusVariant() {
        switch (this.stats.syncStatus) {
            case 'Success':
                return 'success';
            case 'Error':
                return 'error';
            case 'In Progress':
                return 'warning';
            default:
                return 'neutral';
        }
    }
    
    // Event handlers
    handleRefresh() {
        this.isLoading = true;
        
        // Refresh both wire methods
        return Promise.all([
            refreshApex(this.wiredStats),
            refreshApex(this.wiredRecentLeads)
        ]).then(() => {
            this.isLoading = false;
            this.showToast('Success', 'Dashboard refreshed successfully', 'success');
        }).catch(error => {
            this.isLoading = false;
            this.showToast('Error', 'Failed to refresh dashboard: ' + error.body.message, 'error');
        });
    }
    
    handleSyncNow() {
        this.isLoading = true;
        
        syncWithExternalSystem()
            .then(result => {
                this.isLoading = false;
                if (result.success) {
                    this.showToast('Success', 'Sync initiated successfully', 'success');
                    // Refresh data after sync
                    this.handleRefresh();
                } else {
                    this.showToast('Error', 'Sync failed: ' + result.message, 'error');
                }
            })
            .catch(error => {
                this.isLoading = false;
                this.showToast('Error', 'Sync failed: ' + error.body.message, 'error');
            });
    }
    
    handleLeadClick(event) {
        const leadId = event.currentTarget.dataset.leadId;
        
        // Navigate to lead record
        this[NavigationMixin.Navigate]({
            type: 'standard__recordPage',
            attributes: {
                recordId: leadId,
                objectApiName: 'Lead',
                actionName: 'view'
            }
        });
    }
    
    // Utility methods
    showToast(title, message, variant) {
        const event = new ShowToastEvent({
            title: title,
            message: message,
            variant: variant
        });
        this.dispatchEvent(event);
    }
    
    formatDateTime(dateTimeString) {
        if (!dateTimeString) return 'N/A';
        
        try {
            const date = new Date(dateTimeString);
            return date.toLocaleString();
        } catch (error) {
            return 'Invalid Date';
        }
    }
    
    formatCurrency(amount) {
        if (!amount) return '$0';
        
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: 'USD'
        }).format(amount);
    }
    
    getLeadPriorityVariant(priority) {
        switch (priority) {
            case 'High':
                return 'error';
            case 'Medium':
                return 'warning';
            case 'Low':
                return 'success';
            default:
                return 'neutral';
        }
    }
    
    getStatusVariant(status) {
        switch (status) {
            case 'New':
                return 'brand';
            case 'Working - Contacted':
                return 'warning';
            case 'Qualified':
                return 'success';
            case 'Unqualified':
                return 'error';
            default:
                return 'neutral';
        }
    }
}
