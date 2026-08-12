import React from 'react';
import { Shield, Play, Pause, Zap, FileUp, RefreshCw, Activity, AlertOctagon } from 'lucide-react';

export default function Header({ 
  isConnected, 
  isPlaying, 
  speed, 
  threshold,
  onTogglePlay, 
  onSpeedChange, 
  onInjectAttack, 
  onRetrain, 
  onFileUpload 
}) {
  return (
    <header className="glass-panel p-4 mb-6 flex flex-wrap items-center justify-between gap-4 border-b border-slate-800">
      {/* Title & Status */}
      <div className="flex items-center gap-3">
        <div className="p-2.5 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400 glow-anomaly">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white">AI Packet Anomaly Guard</h1>
            <span className="px-2 py-0.5 text-xs font-semibold bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded-full flex items-center gap-1">
              <AlertOctagon className="w-3 h-3" /> Top 0.1% Detection
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
            <span>Isolation Forest Unsupervised Engine</span>
            <span>•</span>
            <span className="flex items-center gap-1 font-mono text-cyan-400">
              <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'}`}></span>
              {isConnected ? 'LIVE WS STREAM' : 'DISCONNECTED'}
            </span>
            <span>•</span>
            <span className="font-mono text-amber-400">Cutoff Threshold: {threshold}</span>
          </p>
        </div>
      </div>

      {/* Stream Controls */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Play/Pause Button */}
        <button
          onClick={onTogglePlay}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-all duration-200 ${
            isPlaying 
              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 hover:bg-amber-500/30' 
              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30'
          }`}
        >
          {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
          {isPlaying ? 'PAUSE' : 'RESUME'}
        </button>

        {/* Speed Selector */}
        <div className="flex items-center bg-slate-900/80 border border-slate-800 rounded-lg p-1 text-xs">
          {[1.0, 2.0, 5.0, 10.0].map((s) => (
            <button
              key={s}
              onClick={() => onSpeedChange(s)}
              className={`px-2.5 py-1 rounded font-mono font-medium transition-all ${
                speed === s 
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' 
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {s}x
            </button>
          ))}
        </div>

        {/* Attack Injector Dropdown */}
        <div className="relative group">
          <button className="flex items-center gap-2 px-3.5 py-2 bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/40 rounded-lg text-sm font-medium transition-all">
            <Zap className="w-4 h-4 text-rose-400" />
            Inject 0.1% Attack
          </button>
          <div className="absolute right-0 top-full mt-1 w-56 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden hidden group-hover:block z-50">
            <button 
              onClick={() => onInjectAttack('shellcode_high_entropy')}
              className="w-full text-left px-3.5 py-2.5 text-xs text-slate-300 hover:bg-rose-500/20 hover:text-white transition-all border-b border-slate-800/60"
            >
              💣 High Entropy Shellcode (7.8+)
            </button>
            <button 
              onClick={() => onInjectAttack('syn_fin_scan')}
              className="w-full text-left px-3.5 py-2.5 text-xs text-slate-300 hover:bg-rose-500/20 hover:text-white transition-all border-b border-slate-800/60"
            >
              ⚡ Illegal TCP Flags (SYN+FIN Scan)
            </button>
            <button 
              onClick={() => onInjectAttack('reverse_shell')}
              className="w-full text-left px-3.5 py-2.5 text-xs text-slate-300 hover:bg-rose-500/20 hover:text-white transition-all border-b border-slate-800/60"
            >
              🔌 Reverse Shell (C2 Port 4444)
            </button>
            <button 
              onClick={() => onInjectAttack('ddos_burst')}
              className="w-full text-left px-3.5 py-2.5 text-xs text-slate-300 hover:bg-rose-500/20 hover:text-white transition-all"
            >
              🌊 DDoS SYN Flood Burst
            </button>
          </div>
        </div>

        {/* Upload PCAP Button */}
        <label className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-sm font-medium cursor-pointer transition-all">
          <FileUp className="w-4 h-4 text-cyan-400" />
          PCAP Upload
          <input 
            type="file" 
            accept=".pcap,.pcapng,.cap" 
            onChange={onFileUpload} 
            className="hidden" 
          />
        </label>

        {/* Retrain Button */}
        <button
          onClick={onRetrain}
          className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700 rounded-lg text-sm transition-all"
          title="Retrain Isolation Forest Model"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
}
