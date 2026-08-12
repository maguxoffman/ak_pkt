import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import MetricsOverview from './components/MetricsOverview';
import AnomalyStreamFeed from './components/AnomalyStreamFeed';
import LivePacketTable from './components/LivePacketTable';
import AnalyticsCharts from './components/AnalyticsCharts';
import WiresharkInspectorModal from './components/WiresharkInspectorModal';
import { AlertOctagon, Activity, BarChart3, ShieldAlert } from 'lucide-react';

const API_BASE = 'http://localhost:8000';
const WS_URL = 'ws://localhost:8000/ws/packets';

export default function App() {
  const [isConnected, setIsConnected] = useState(false);
  const [packets, setPackets] = useState([]);
  const [anomalyPackets, setAnomalyPackets] = useState([]);
  const [stats, setStats] = useState({
    total_packets: 0,
    anomalies_01_count: 0,
    max_score: 0,
    threshold: 0.65,
    top_suspicious_ips: [],
    protocol_counts: {}
  });
  const [isPlaying, setIsPlaying] = useState(true);
  const [speed, setSpeed] = useState(1.0);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [activeTab, setActiveTab] = useState('anomaly'); // 'anomaly', 'live', 'analytics'

  const wsRef = useRef(null);

  // Connect WebSocket
  useEffect(() => {
    let ws;
    const connectWS = () => {
      ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('[WebSocket] Connected to packet stream');
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'INITIAL_STATE') {
            setStats(msg.stats);
            setIsPlaying(msg.is_playing);
            setSpeed(msg.speed);
          } else if (msg.type === 'PACKET_EVENT') {
            const pkt = msg.packet;
            setStats(msg.stats);

            // Buffer packets
            setPackets((prev) => [pkt, ...prev].slice(0, 100));

            // If 0.1% anomaly score outlier
            if (pkt.is_anomaly_01) {
              setAnomalyPackets((prev) => [pkt, ...prev].slice(0, 50));
            }
          }
        } catch (err) {
          console.error('[WebSocket] Error parsing message', err);
        }
      };

      ws.onclose = () => {
        console.log('[WebSocket] Disconnected. Reconnecting in 2s...');
        setIsConnected(false);
        setTimeout(connectWS, 2000);
      };

      ws.onerror = (err) => {
        console.error('[WebSocket] Error', err);
        ws.close();
      };
    };

    connectWS();

    return () => {
      if (ws) ws.close();
    };
  }, []);

  // Controls Handlers
  const handleTogglePlay = async () => {
    const nextState = !isPlaying;
    setIsPlaying(nextState);
    try {
      await fetch(`${API_BASE}/api/control`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: nextState ? 'play' : 'pause' })
      });
    } catch (e) {
      console.error('Error toggling stream state:', e);
    }
  };

  const handleSpeedChange = async (s) => {
    setSpeed(s);
    try {
      await fetch(`${API_BASE}/api/control`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'set_speed', speed: s })
      });
    } catch (e) {
      console.error('Error changing speed:', e);
    }
  };

  const handleInjectAttack = async (attackType) => {
    try {
      const res = await fetch(`${API_BASE}/api/inject-attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: attackType })
      });
      const data = await res.json();
      if (data.packet) {
        // Automatically switch to 0.1% anomaly tab
        setActiveTab('anomaly');
      }
    } catch (e) {
      console.error('Error injecting attack:', e);
    }
  };

  const handleRetrain = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/retrain`, { method: 'POST' });
      const data = await res.json();
      alert(`Isolation Forest Model Retrained! New 99.9% Cutoff Threshold: ${data.threshold}`);
    } catch (e) {
      console.error('Error retraining model:', e);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`${API_BASE}/api/upload-pcap`, {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (res.ok) {
        alert(`Loaded PCAP: ${data.filename} (${data.packet_count} packets processed)`);
      } else {
        alert(`Error: ${data.detail}`);
      }
    } catch (err) {
      console.error('Error uploading PCAP:', err);
    }
  };

  return (
    <div className="min-h-screen p-4 md:p-8 max-w-7xl mx-auto">
      {/* Header Bar */}
      <Header
        isConnected={isConnected}
        isPlaying={isPlaying}
        speed={speed}
        threshold={stats.threshold || 0.65}
        onTogglePlay={handleTogglePlay}
        onSpeedChange={handleSpeedChange}
        onInjectAttack={handleInjectAttack}
        onRetrain={handleRetrain}
        onFileUpload={handleFileUpload}
      />

      {/* Top Metrics Cards Overview */}
      <MetricsOverview stats={stats} />

      {/* Analytics Charts Row */}
      <AnalyticsCharts packets={packets} stats={stats} />

      {/* Main Tabs Navigation */}
      <div className="glass-panel p-2 mb-6 flex items-center justify-between gap-2 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('anomaly')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'anomaly'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 glow-anomaly'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <AlertOctagon className="w-4 h-4 text-rose-400" />
            🔴 Top 0.1% Anomaly Feed ({anomalyPackets.length})
          </button>

          <button
            onClick={() => setActiveTab('live')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'live'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <Activity className="w-4 h-4 text-cyan-400" />
            📡 Live Packet Stream ({packets.length})
          </button>
        </div>

        <div className="text-xs text-slate-500 font-mono hidden sm:block">
          Unsupervised Isolation Forest • 99.9 Percentile Cutoff
        </div>
      </div>

      {/* Tab Content Rendering */}
      {activeTab === 'anomaly' && (
        <AnomalyStreamFeed
          anomalyPackets={anomalyPackets}
          onInspectPacket={(pkt) => setSelectedPacket(pkt)}
          onInjectTest={() => handleInjectAttack('shellcode_high_entropy')}
        />
      )}

      {activeTab === 'live' && (
        <LivePacketTable
          packets={packets}
          onInspectPacket={(pkt) => setSelectedPacket(pkt)}
        />
      )}

      {/* Wireshark Hex/Protocol Tree Inspector Modal */}
      {selectedPacket && (
        <WiresharkInspectorModal
          packet={selectedPacket}
          onClose={() => setSelectedPacket(null)}
        />
      )}
    </div>
  );
}
