self.addEventListener('push', event => {
    let notification = {};
    try {
        notification = event.data ? event.data.json() : {};
    } catch (error) {
        notification = { title: 'EXP milestone reached', body: event.data ? event.data.text() : '' };
    }
    event.waitUntil(self.registration.showNotification(notification.title || 'EXP milestone reached', {
        body: notification.body || 'An account reached an EXP milestone.',
        tag: notification.tag || 'exp-milestone',
        data: { url: notification.url || '/' }
    }));
});

self.addEventListener('notificationclick', event => {
    event.notification.close();
    const target = new URL(event.notification.data && event.notification.data.url || '/', self.location.origin).href;
    event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
        for (const client of clients) {
            if (client.url === target && 'focus' in client) return client.focus();
        }
        return self.clients.openWindow(target);
    }));
});
