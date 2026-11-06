import { Server, Globe } from "lucide-react";
import { AssessmentDetail } from "@/lib/types";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface TopologyGridProps {
  assessment: AssessmentDetail;
}

export function TopologyGrid({ assessment }: TopologyGridProps) {
  const assets = assessment.discovered_assets || [];
  const services = assessment.discovered_services || [];

  return (
    <Card className="border-border/70">
      <CardHeader className="border-b border-border/50 py-3 px-4 flex flex-row items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-muted-foreground/60" />
          <CardTitle className="text-xs uppercase tracking-wider font-semibold">
            Attack Surface Topology
          </CardTitle>
        </div>
        <Badge variant="outline" className="text-[10px] font-normal">
          {assets.length} Hosts · {services.length} Services
        </Badge>
      </CardHeader>

      <CardContent className="space-y-4 p-4">
        {/* Discovered Assets */}
        <div>
          <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-2">
            Discovered Targets
          </div>
          <div className="flex flex-wrap gap-2">
            {assets.length === 0 ? (
              <span className="text-xs text-muted-foreground">No hosts discovered yet...</span>
            ) : (
              assets.map((asset, i) => (
                <Badge
                  key={i}
                  variant="secondary"
                  className="gap-1.5 px-2.5 py-1 text-xs font-mono font-normal"
                >
                  <Server className="h-3 w-3 text-muted-foreground/70" />
                  {asset}
                </Badge>
              ))
            )}
          </div>
        </div>

        {/* Discovered Open Services */}
        <div>
          <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-2">
            Open Services & Ports
          </div>
          <div className="space-y-2">
            {services.length === 0 ? (
              <span className="text-xs text-muted-foreground">Reconnaissance in progress...</span>
            ) : (
              services.map((svc, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between rounded-md border border-border/60 bg-muted/20 p-2.5 text-xs font-mono"
                >
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px] font-medium border-border/70">
                      Port {svc.port}
                    </Badge>
                    <span className="text-foreground font-medium font-sans">
                      {svc.service || svc.product || "unknown"}
                    </span>
                  </div>
                  <span className="text-muted-foreground text-[11px]">
                    {svc.version || "n/a"}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
