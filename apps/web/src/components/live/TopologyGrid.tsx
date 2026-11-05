import { Server, Globe, Shield } from "lucide-react";
import { AssessmentDetail } from "@/lib/types";

interface TopologyGridProps {
  assessment: AssessmentDetail;
}

export function TopologyGrid({ assessment }: TopologyGridProps) {
  const assets = assessment.discovered_assets || [];
  const services = assessment.discovered_services || [];

  return (
    <div className="glass-panel rounded-2xl border border-cyber-border p-4 sm:p-5 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-cyan-400" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
            Attack Surface Topology
          </h3>
        </div>
        <span className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded">
          {assets.length} Hosts · {services.length} Services
        </span>
      </div>

      {/* Discovered Assets */}
      <div>
        <div className="text-[11px] font-mono text-cyber-muted uppercase tracking-wider mb-2">
          Discovered Targets
        </div>
        <div className="flex flex-wrap gap-2">
          {assets.length === 0 ? (
            <span className="text-xs font-mono text-cyber-muted">No hosts discovered yet...</span>
          ) : (
            assets.map((asset, i) => (
              <span
                key={i}
                className="inline-flex items-center gap-1.5 rounded-lg border border-indigo-500/30 bg-indigo-500/10 px-2.5 py-1 text-xs font-mono font-semibold text-indigo-300"
              >
                <Server className="h-3 w-3 text-indigo-400" />
                {asset}
              </span>
            ))
          )}
        </div>
      </div>

      {/* Discovered Open Services */}
      <div>
        <div className="text-[11px] font-mono text-cyber-muted uppercase tracking-wider mb-2">
          Open Services & Versions
        </div>
        <div className="space-y-2">
          {services.length === 0 ? (
            <span className="text-xs font-mono text-cyber-muted">Recon in progress...</span>
          ) : (
            services.map((svc, i) => (
              <div
                key={i}
                className="flex items-center justify-between rounded-xl border border-cyber-border bg-cyber-bg/60 p-2.5 font-mono text-xs"
              >
                <div className="flex items-center gap-2">
                  <span className="rounded bg-cyan-500/10 px-2 py-0.5 text-cyan-300 font-bold border border-cyan-500/30">
                    Port {svc.port}
                  </span>
                  <span className="text-white font-medium">
                    {svc.service || svc.product || "HTTP Service"}
                  </span>
                </div>
                {svc.version && (
                  <span className="text-cyber-muted text-[11px] bg-cyber-panel px-2 py-0.5 rounded border border-cyber-border">
                    v{svc.version}
                  </span>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

