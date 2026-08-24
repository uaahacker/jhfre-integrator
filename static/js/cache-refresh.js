/**
 * Cache refresh utilities for immediate permission and menu updates
 */
class CacheRefreshManager {
    constructor() {
        this.init();
    }

    init() {
        // Auto-refresh functionality for permission pages
        if (window.location.pathname.includes('/permissions/')) {
            this.setupPermissionPageRefresh();
        }
        
        // Setup cache refresh for all pages
        this.setupGlobalCacheRefresh();
    }

    setupPermissionPageRefresh() {
        // Listen for successful permission saves
        document.addEventListener('DOMContentLoaded', () => {
            const saveButtons = document.querySelectorAll('[data-save-permissions]');
            saveButtons.forEach(button => {
                button.addEventListener('click', (e) => {
                    // Add a flag to refresh after save
                    sessionStorage.setItem('refreshAfterPermissionSave', 'true');
                });
            });

            // Check if we need to refresh after permission save
            if (sessionStorage.getItem('refreshAfterPermissionSave') === 'true') {
                sessionStorage.removeItem('refreshAfterPermissionSave');
                this.showRefreshNotification();
                // Auto-refresh after 3 seconds or on user interaction
                setTimeout(() => {
                    this.refreshPage();
                }, 3000);
            }
        });
    }

    setupGlobalCacheRefresh() {
        // Listen for cache invalidation events
        window.addEventListener('cacheInvalidated', (event) => {
            this.handleCacheInvalidation(event.detail);
        });
    }

    handleCacheInvalidation(details) {
        console.log('Cache invalidated:', details);
        
        // Show notification
        this.showRefreshNotification();
        
        // Auto-refresh if the current user is affected
        if (details.affectedUsers && details.affectedUsers.includes(window.currentUserId)) {
            setTimeout(() => {
                this.refreshPage();
            }, 2000);
        }
    }

    showRefreshNotification() {
        // Remove existing notifications
        const existingNotifications = document.querySelectorAll('.cache-refresh-notification');
        existingNotifications.forEach(n => n.remove());

        // Create notification
        const notification = document.createElement('div');
        notification.className = 'alert alert-info cache-refresh-notification';
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            max-width: 400px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        `;
        notification.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="ki-duotone ki-information-5 fs-2 me-2">
                    <span class="path1"></span>
                    <span class="path2"></span>
                    <span class="path3"></span>
                </i>
                <div class="flex-grow-1">
                    <strong>Permissions Updated!</strong><br>
                    <small>The page will refresh automatically to show changes.</small>
                </div>
                <button type="button" class="btn btn-sm btn-light ms-2" onclick="this.parentElement.parentElement.remove()">
                    <i class="ki-duotone ki-cross fs-3">
                        <span class="path1"></span>
                        <span class="path2"></span>
                    </i>
                </button>
            </div>
        `;

        document.body.appendChild(notification);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    refreshPage() {
        // Add loading indicator
        const loadingIndicator = document.createElement('div');
        loadingIndicator.innerHTML = `
            <div class="d-flex align-items-center justify-content-center" style="
                position: fixed; 
                top: 0; 
                left: 0; 
                width: 100%; 
                height: 100%; 
                background: rgba(255,255,255,0.8); 
                z-index: 10000;
            ">
                <div class="spinner-border text-primary me-2" role="status"></div>
                <span>Refreshing to show updated permissions...</span>
            </div>
        `;
        document.body.appendChild(loadingIndicator);

        // Refresh the page
        setTimeout(() => {
            window.location.reload();
        }, 1000);
    }

    // Manual cache refresh method
    static async refreshCache(userIds = null) {
        try {
            const response = await fetch('/permissions/refresh-cache/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]')?.value || ''
                },
                body: JSON.stringify({
                    user_ids: userIds
                })
            });

            const result = await response.json();
            
            if (result.success) {
                console.log('Cache refreshed successfully:', result.message);
                
                // Trigger cache invalidation event
                window.dispatchEvent(new CustomEvent('cacheInvalidated', {
                    detail: {
                        affectedUsers: userIds,
                        message: result.message
                    }
                }));
                
                return true;
            } else {
                console.error('Cache refresh failed:', result.message);
                return false;
            }
        } catch (error) {
            console.error('Cache refresh error:', error);
            return false;
        }
    }
}

// Initialize cache refresh manager
document.addEventListener('DOMContentLoaded', () => {
    window.cacheRefreshManager = new CacheRefreshManager();
});

// Global function for manual cache refresh
window.refreshCache = CacheRefreshManager.refreshCache;
