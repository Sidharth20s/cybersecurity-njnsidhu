import React, { useState, useEffect, useRef } from 'react';

const SIEMDashboard = () => {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    total_alerts: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    new: 0,
    event_count: 0,
  });
  const [events, setEvents] = useState([]);
  const [threatIntel, setThreatIntel] = useState({
    top_malicious_ips: [],
    risky_users: [],
    alert_rate_last_hour: 0,
  });
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [filter, setFilter] = useState({ status: 'all', severity: 'all' });
  const wsRef = useRef(null);

  // Fetch initial data
  useEffect(() => {
    fetchAlerts();
    fetchStats();
    fetchThreatIntel();
    connectWebSocket();

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const fetchAlerts = async () => {
    try {
      const params = new URLSearchParams();
      if (filter.status !== 'all') params.append('status', filter.status);
      if (filter.severity !== 'all') params.append('severity', filter.severity);

      const response = await fetch(`http://localhost:8000/api/alerts?${params}`);
      const data = await response.json();
      setAlerts(data);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/stats');
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  const fetchThreatIntel = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/threat-intelligence');
      const data = await response.json();
      setThreatIntel(data);
    } catch (error) {
      console.error('Failed to fetch threat intel:', error);
    }
  };

  const connectWebSocket = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//localhost:8000/ws/events`;

    wsRef.current = new WebSocket(wsUrl);

    wsRef.current.onmessage = (event) => {
      const message = JSON.parse(event.data);

      if (message.type === 'alert') {
        setAlerts((prev) => [message.data, ...prev].slice(0, 100));
        setStats((prev) => ({
          ...prev,
          total_alerts: prev.total_alerts + 1,
          new: prev.new + 1,
        }));
      } else if (message.type === 'event') {
        setEvents((prev) => [message.data, ...prev].slice(0, 100));
        setStats((prev) => ({
          ...prev,
          event_count: prev.event_count + 1,
        }));
      }
    };

    wsRef.current.onerror = () => {
      setTimeout(connectWebSocket, 3000);
    };
  };

  const acknowledgeAlert = async (alertId) => {
    try {
      await fetch(`http://localhost:8000/api/alerts/${alertId}/acknowledge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assigned_to: 'SOC Team' }),
      });
      fetchAlerts();
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
    }
  };

  const resolveAlert = async (alertId) => {
    try {
      await fetch(`http://localhost:8000/api/alerts/${alertId}/resolve`, {
        method: 'POST',
      });
      fetchAlerts();
    } catch (error) {
      console.error('Failed to resolve alert:', error);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: '#e24b4a',
      HIGH: '#ba7517',
      MEDIUM: '#378add',
      LOW: '#3b6d11',
    };
    return colors[severity] || '#888780';
  };

  const getStatusBadge = (status) => {
    const styles = {
      new: { bg: 'rgba(226, 75, 74, 0.1)', color: '#e24b4a', label: 'New' },
      acknowledged: { bg: 'rgba(186, 117, 23, 0.1)', color: '#ba7517', label: 'Acknowledged' },
      investigating: { bg: 'rgba(55, 138, 221, 0.1)', color: '#378add', label: 'Investigating' },
      resolved: { bg: 'rgba(59, 109, 17, 0.1)', color: '#3b6d11', label: 'Resolved' },
    };
    return styles[status] || styles.new;
  };

  return (
    <div style={{ fontFamily: 'var(--font-sans)', color: 'var(--color-text-primary)', backgroundColor: 'var(--color-background-tertiary)', minHeight: '100vh', padding: '20px' }}>
      {/* Header */}
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ fontSize: '28px', fontWeight: '500', margin: '0 0 8px 0' }}>Security Operations Center</h1>
        <p style={{ fontSize: '14px', color: 'var(--color-text-secondary)', margin: '0' }}>Enterprise SIEM Dashboard</p>
      </div>

      {/* KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '12px', marginBottom: '24px' }}>
        <div style={{ background: 'var(--color-background-secondary)', borderRadius: 'var(--border-radius-md)', padding: '16px' }}>
          <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)', margin: '0 0 8px 0' }}>Total Alerts</p>
          <p style={{ fontSize: '24px', fontWeight: '500', margin: '0' }}>{stats.total_alerts}</p>
        </div>

        <div style={{ background: 'var(--color-background-secondary)', borderRadius: 'var(--border-radius-md)', padding: '16px', borderLeft: '3px solid #e24b4a' }}>
          <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)', margin: '0 0 8px 0' }}>Critical</p>
          <p style={{ fontSize: '24px', fontWeight: '500', margin: '0', color: '#e24b4a' }}>{stats.critical}</p>
        </div>

        <div style={{ background: 'var(--color-background-secondary)', borderRadius: 'var(--border-radius-md)', padding: '16px', borderLeft: '3px solid #ba7517' }}>
          <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)', margin: '0 0 8px 0' }}>High</p>
          <p style={{ fontSize: '24px', fontWeight: '500', margin: '0', color: '#ba7517' }}>{stats.high}</p>
        </div>

        <div style={{ background: 'var(--color-background-secondary)', borderRadius: 'var(--border-radius-md)', padding: '16px', borderLeft: '3px solid #378add' }}>
          <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)', margin: '0 0 8px 0' }}>Medium</p>
          <p style={{ fontSize: '24px', fontWeight: '500', margin: '0', color: '#378add' }}>{stats.medium}</p>
        </div>

        <div style={{ background: 'var(--color-background-secondary)', borderRadius: 'var(--border-radius-md)', padding: '16px', borderLeft: '3px solid #3b6d11' }}>
          <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)', margin: '0 0 8px 0' }}>Low</p>
          <p style={{ fontSize: '24px', fontWeight: '500', margin: '0', color: '#3b6d11' }}>{stats.low}</p>
        </div>

        <div style={{ background: 'var(--color-background-secondary)', borderRadius: 'var(--border-radius-md)', padding: '16px' }}>
          <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)', margin: '0 0 8px 0' }}>Events</p>
          <p style={{ fontSize: '24px', fontWeight: '500', margin: '0' }}>{stats.event_count}</p>
        </div>
      </div>

      {/* Main Content Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: '16px', marginBottom: '24px' }}>
        {/* Alerts Section */}
        <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 'var(--border-radius-lg)', padding: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: '500', margin: '0' }}>Recent Alerts</h2>
            <div style={{ display: 'flex', gap: '8px' }}>
              <select
                value={filter.status}
                onChange={(e) => {
                  setFilter({ ...filter, status: e.target.value });
                  fetchAlerts();
                }}
                style={{ fontSize: '12px', padding: '6px 8px', borderRadius: 'var(--border-radius-md)', border: '0.5px solid var(--color-border-tertiary)', background: 'var(--color-background-secondary)' }}
              >
                <option value="all">All Status</option>
                <option value="new">New</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="resolved">Resolved</option>
              </select>

              <select
                value={filter.severity}
                onChange={(e) => {
                  setFilter({ ...filter, severity: e.target.value });
                  fetchAlerts();
                }}
                style={{ fontSize: '12px', padding: '6px 8px', borderRadius: 'var(--border-radius-md)', border: '0.5px solid var(--color-border-tertiary)', background: 'var(--color-background-secondary)' }}
              >
                <option value="all">All Severity</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>

          <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
            {alerts.length === 0 ? (
              <p style={{ fontSize: '14px', color: 'var(--color-text-secondary)', textAlign: 'center', padding: '24px' }}>No alerts</p>
            ) : (
              alerts.map((alert) => {
                const statusStyle = getStatusBadge(alert.status);
                return (
                  <div
                    key={alert.id}
                    style={{
                      borderLeft: `3px solid ${getSeverityColor(alert.severity)}`,
                      padding: '12px',
                      marginBottom: '8px',
                      background: 'var(--color-background-secondary)',
                      borderRadius: 'var(--border-radius-md)',
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                    }}
                    onClick={() => setSelectedAlert(alert)}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.boxShadow = 'none';
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                      <div style={{ flex: 1 }}>
                        <p style={{ fontSize: '13px', fontWeight: '500', margin: '0 0 4px 0' }}>{alert.title}</p>
                        <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)', margin: '0', lineHeight: '1.4' }}>{alert.description}</p>
                      </div>
                      <div style={{ display: 'flex', gap: '4px', marginLeft: '8px' }}>
                        <span
                          style={{
                            fontSize: '11px',
                            padding: '2px 6px',
                            borderRadius: '3px',
                            background: statusStyle.bg,
                            color: statusStyle.color,
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {statusStyle.label}
                        </span>
                        <span
                          style={{
                            fontSize: '11px',
                            padding: '2px 6px',
                            borderRadius: '3px',
                            background: `${getSeverityColor(alert.severity)}20`,
                            color: getSeverityColor(alert.severity),
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {alert.severity}
                        </span>
                      </div>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--color-text-tertiary)' }}>
                      {new Date(alert.timestamp).toLocaleString()} • {alert.event_count} event{alert.event_count !== 1 ? 's' : ''}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Threat Intelligence Sidebar */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Top Malicious IPs */}
          <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 'var(--border-radius-lg)', padding: '12px' }}>
            <h3 style={{ fontSize: '13px', fontWeight: '500', margin: '0 0 10px 0' }}>Top Malicious IPs</h3>
            <div style={{ fontSize: '12px' }}>
              {threatIntel.top_malicious_ips.slice(0, 5).map((item, idx) => (
                <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: idx < 4 ? '0.5px solid var(--color-border-tertiary)' : 'none' }}>
                  <span style={{ color: 'var(--color-text-secondary)' }}>{item[0]}</span>
                  <span style={{ fontWeight: '500' }}>{item[1]}</span>
                </div>
              ))}
              {threatIntel.top_malicious_ips.length === 0 && <p style={{ color: 'var(--color-text-secondary)', margin: '0' }}>None detected</p>}
            </div>
          </div>

          {/* Risky Users */}
          <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 'var(--border-radius-lg)', padding: '12px' }}>
            <h3 style={{ fontSize: '13px', fontWeight: '500', margin: '0 0 10px 0' }}>Risky Users</h3>
            <div style={{ fontSize: '12px' }}>
              {threatIntel.risky_users.slice(0, 5).map((item, idx) => (
                <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: idx < 4 ? '0.5px solid var(--color-border-tertiary)' : 'none' }}>
                  <span style={{ color: 'var(--color-text-secondary)' }}>{item[0]}</span>
                  <span style={{ fontWeight: '500' }}>{item[1]}</span>
                </div>
              ))}
              {threatIntel.risky_users.length === 0 && <p style={{ color: 'var(--color-text-secondary)', margin: '0' }}>None detected</p>}
            </div>
          </div>

          {/* Alert Rate */}
          <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 'var(--border-radius-lg)', padding: '12px' }}>
            <h3 style={{ fontSize: '13px', fontWeight: '500', margin: '0 0 8px 0' }}>Last Hour</h3>
            <p style={{ fontSize: '20px', fontWeight: '500', margin: '0', color: '#378add' }}>{threatIntel.alert_rate_last_hour}</p>
            <p style={{ fontSize: '11px', color: 'var(--color-text-secondary)', margin: '4px 0 0 0' }}>alerts generated</p>
          </div>
        </div>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <div
          style={{
            position: 'fixed',
            inset: '0',
            backgroundColor: 'rgba(0,0,0,0.45)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: '1000',
          }}
          onClick={() => setSelectedAlert(null)}
        >
          <div
            style={{
              background: 'var(--color-background-primary)',
              borderRadius: 'var(--border-radius-lg)',
              padding: '24px',
              maxWidth: '500px',
              width: '90%',
              maxHeight: '80vh',
              overflowY: 'auto',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
              <div>
                <h2 style={{ fontSize: '16px', fontWeight: '500', margin: '0 0 4px 0' }}>{selectedAlert.title}</h2>
                <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)', margin: '0' }}>Rule: {selectedAlert.rule_name}</p>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                style={{ background: 'none', border: 'none', fontSize: '20px', cursor: 'pointer', color: 'var(--color-text-secondary)' }}
              >
                ✕
              </button>
            </div>

            <div style={{ marginBottom: '16px', fontSize: '13px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span style={{ color: 'var(--color-text-secondary)' }}>Severity</span>
                <span
                  style={{
                    padding: '2px 8px',
                    borderRadius: '3px',
                    background: `${getSeverityColor(selectedAlert.severity)}20`,
                    color: getSeverityColor(selectedAlert.severity),
                    fontWeight: '500',
                  }}
                >
                  {selectedAlert.severity}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span style={{ color: 'var(--color-text-secondary)' }}>Status</span>
                <span style={{ fontWeight: '500' }}>{getStatusBadge(selectedAlert.status).label}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span style={{ color: 'var(--color-text-secondary)' }}>Related Events</span>
                <span style={{ fontWeight: '500' }}>{selectedAlert.event_count}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--color-text-secondary)' }}>Timestamp</span>
                <span style={{ fontWeight: '500' }}>{new Date(selectedAlert.timestamp).toLocaleString()}</span>
              </div>
            </div>

            <p style={{ fontSize: '13px', padding: '12px', background: 'var(--color-background-secondary)', borderRadius: 'var(--border-radius-md)', margin: '0 0 16px 0' }}>
              {selectedAlert.description}
            </p>

            <div style={{ display: 'flex', gap: '8px' }}>
              {selectedAlert.status === 'new' && (
                <button
                  onClick={() => {
                    acknowledgeAlert(selectedAlert.id);
                    setSelectedAlert(null);
                  }}
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    background: 'var(--color-background-info)',
                    color: 'var(--color-text-info)',
                    border: 'none',
                    borderRadius: 'var(--border-radius-md)',
                    cursor: 'pointer',
                    fontSize: '13px',
                    fontWeight: '500',
                  }}
                >
                  Acknowledge
                </button>
              )}
              {selectedAlert.status !== 'resolved' && (
                <button
                  onClick={() => {
                    resolveAlert(selectedAlert.id);
                    setSelectedAlert(null);
                  }}
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    background: 'var(--color-background-success)',
                    color: 'var(--color-text-success)',
                    border: 'none',
                    borderRadius: 'var(--border-radius-md)',
                    cursor: 'pointer',
                    fontSize: '13px',
                    fontWeight: '500',
                  }}
                >
                  Resolve
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Connection Status */}
      <div
        style={{
          position: 'fixed',
          bottom: '20px',
          right: '20px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '12px',
          color: 'var(--color-text-secondary)',
        }}
      >
        <span
          style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: wsRef.current?.readyState === 1 ? '#3b6d11' : '#ba7517',
            display: 'inline-block',
          }}
        />
        {wsRef.current?.readyState === 1 ? 'Connected' : 'Connecting'}
      </div>
    </div>
  );
};

export default SIEMDashboard;
