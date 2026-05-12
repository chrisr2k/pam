/**
 * Live Updates for PAM
 * Polls the server every 5 seconds for real-time status updates
 * and updates the UI without requiring a full page refresh.
 */

(function() {
    'use strict';

    const POLL_INTERVAL_MS = 5000; // 5 seconds
    let pollTimer = null;

    /**
     * Fetch live updates from the server.
     */
    function fetchUpdates() {
        const pollUrl = document.getElementById('live-updates-data');
        if (!pollUrl) return;

        const url = pollUrl.getAttribute('data-poll-url');
        if (!url) return;

        fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
            },
            credentials: 'same-origin',
        })
        .then(response => {
            if (!response.ok) throw new Error('Poll failed');
            return response.json();
        })
        .then(data => {
            updateActiveSessions(data);
            updatePendingApprovals(data);
            updateRecentRequests(data);
            updateNavBadge(data);
        })
        .catch(err => {
            // Silently fail - don't spam console on network errors
            console.debug('PAM live update poll failed:', err);
        });
    }

    /**
     * Update the Active Sessions table on the dashboard.
     */
    function updateActiveSessions(data) {
        const container = document.getElementById('active-sessions-body');
        const emptyMsg = document.getElementById('active-sessions-empty');
        const tableDiv = document.getElementById('active-sessions-table');
        const statCard = document.getElementById('stat-active-count');
        if (!container) return;

        if (data.active_count === 0) {
            container.innerHTML = '';
            if (emptyMsg) emptyMsg.style.display = '';
            if (tableDiv) tableDiv.style.display = 'none';
            if (statCard) statCard.textContent = '0';
            return;
        }

        if (emptyMsg) emptyMsg.style.display = 'none';
        if (tableDiv) tableDiv.style.display = '';
        if (statCard) statCard.textContent = data.active_count;

        let html = '';
        data.active_sessions.forEach(session => {
            const expiresIn = session.expires_in_seconds;
            let expiresText;
            if (expiresIn <= 0) {
                expiresText = '<span class="text-danger">Expired</span>';
            } else if (expiresIn < 60) {
                expiresText = '<1 min';
            } else if (expiresIn < 3600) {
                expiresText = Math.floor(expiresIn / 60) + ' min';
            } else {
                const hours = Math.floor(expiresIn / 3600);
                const mins = Math.floor((expiresIn % 3600) / 60);
                expiresText = hours + 'h ' + mins + 'm';
            }

            const statusClass = 'badge-status-' + session.status.toLowerCase();
            html += '<tr>' +
                '<td><a href="/requests/' + session.id + '/">' + escapeHtml(session.role) + '</a></td>' +
                '<td><span class="badge bg-secondary">' + escapeHtml(session.provider) + '</span></td>' +
                '<td>' + expiresText + '</td>' +
                '<td><span class="badge ' + statusClass + '">' + escapeHtml(session.status_display) + '</span></td>' +
                '<td>' +
                '<form method="post" action="/requests/' + session.id + '/revoke/" style="display:inline;">' +
                '<input type="hidden" name="csrfmiddlewaretoken" value="' + getCsrfToken() + '">' +
                '<button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm(\'Revoke access to ' + escapeHtml(session.role) + '?\')">Revoke</button>' +
                '</form>' +
                '</td>' +
                '</tr>';
        });
        container.innerHTML = html;
    }

    /**
     * Update the Pending Approvals section on the dashboard.
     */
    function updatePendingApprovals(data) {
        const container = document.getElementById('pending-approvals-body');
        const emptyMsg = document.getElementById('pending-approvals-empty');
        const tableDiv = document.getElementById('pending-approvals-table');
        const statCard = document.getElementById('stat-pending-count');
        if (!container) return;

        if (data.pending_count === 0) {
            container.innerHTML = '';
            if (emptyMsg) emptyMsg.style.display = '';
            if (tableDiv) tableDiv.style.display = 'none';
            if (statCard) statCard.textContent = '0';
            return;
        }

        if (emptyMsg) emptyMsg.style.display = 'none';
        if (tableDiv) tableDiv.style.display = '';
        if (statCard) statCard.textContent = data.pending_count;

        let html = '';
        data.pending_approvals.forEach(req => {
            html += '<tr>' +
                '<td>' + escapeHtml(req.requester) + '</td>' +
                '<td>' + escapeHtml(req.role) + '</td>' +
                '<td>' + req.duration + ' min</td>' +
                '<td><a href="/requests/' + req.id + '/" class="btn btn-sm btn-outline-primary">Review</a></td>' +
                '</tr>';
        });
        container.innerHTML = html;
    }

    /**
     * Update the Recent Requests table on the dashboard.
     */
    function updateRecentRequests(data) {
        const container = document.getElementById('recent-requests-body');
        const emptyMsg = document.getElementById('recent-requests-empty');
        const statCard = document.getElementById('stat-recent-count');
        if (!container) return;

        if (!data.recent_requests || data.recent_requests.length === 0) {
            container.innerHTML = '';
            if (emptyMsg) emptyMsg.style.display = '';
            if (statCard) statCard.textContent = '0';
            return;
        }

        if (emptyMsg) emptyMsg.style.display = 'none';
        if (statCard) statCard.textContent = data.recent_requests.length;

        let html = '';
        data.recent_requests.forEach(req => {
            const statusClass = 'badge-status-' + req.status.toLowerCase();
            const date = new Date(req.created_at);
            const dateStr = date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
                ', ' + date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
            html += '<tr>' +
                '<td><a href="/requests/' + req.id + '/">#' + req.id + '</a></td>' +
                '<td>' + escapeHtml(req.role) + '</td>' +
                '<td><span class="badge ' + statusClass + '">' + escapeHtml(req.status_display) + '</span></td>' +
                '<td><small>' + dateStr + '</small></td>' +
                '</tr>';
        });
        container.innerHTML = html;
    }

    /**
     * Update the pending approvals badge in the navigation bar.
     */
    function updateNavBadge(data) {
        const badge = document.getElementById('nav-pending-badge');
        if (!badge) return;

        if (data.pending_count > 0) {
            badge.textContent = data.pending_count;
            badge.style.display = '';
        } else {
            badge.style.display = 'none';
        }
    }

    /**
     * Get CSRF token from the cookie.
     */
    function getCsrfToken() {
        const name = 'csrftoken';
        const value = '; ' + document.cookie;
        const parts = value.split('; ' + name + '=');
        if (parts.length === 2) return parts.pop().split(';').shift();
        return '';
    }

    /**
     * Escape HTML to prevent XSS.
     */
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.appendChild(document.createTextNode(text));
        return div.innerHTML;
    }

    /**
     * Start polling for live updates.
     */
    function startPolling() {
        // Initial fetch
        fetchUpdates();
        // Poll on interval
        pollTimer = setInterval(fetchUpdates, POLL_INTERVAL_MS);
    }

    /**
     * Stop polling.
     */
    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    // Auto-start when DOM is ready, only if the poll URL data attribute exists
    if (document.getElementById('live-updates-data')) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', startPolling);
        } else {
            startPolling();
        }
    }

    // Stop polling when navigating away
    window.addEventListener('beforeunload', stopPolling);
})();
