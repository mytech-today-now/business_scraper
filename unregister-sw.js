// Script to unregister all service workers
console.log('🚨 UNREGISTERING ALL SERVICE WORKERS 🚨');

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.getRegistrations().then(registrations => {
    console.log(`Found ${registrations.length} service worker registrations`);
    
    registrations.forEach((registration, index) => {
      console.log(`Unregistering service worker ${index + 1}:`, registration.scope);
      registration.unregister().then(success => {
        if (success) {
          console.log(`✅ Successfully unregistered service worker ${index + 1}`);
        } else {
          console.log(`❌ Failed to unregister service worker ${index + 1}`);
        }
      }).catch(error => {
        console.error(`❌ Error unregistering service worker ${index + 1}:`, error);
      });
    });
    
    if (registrations.length === 0) {
      console.log('No service workers found to unregister');
    }
  }).catch(error => {
    console.error('Error getting service worker registrations:', error);
  });
} else {
  console.log('Service workers not supported in this browser');
}

// Also clear all caches
if ('caches' in window) {
  caches.keys().then(cacheNames => {
    console.log(`Found ${cacheNames.length} caches to delete`);
    
    return Promise.all(
      cacheNames.map(cacheName => {
        console.log(`Deleting cache: ${cacheName}`);
        return caches.delete(cacheName);
      })
    );
  }).then(() => {
    console.log('✅ All caches deleted');
  }).catch(error => {
    console.error('❌ Error deleting caches:', error);
  });
}

console.log('🔄 Please refresh the page after service workers are unregistered');
