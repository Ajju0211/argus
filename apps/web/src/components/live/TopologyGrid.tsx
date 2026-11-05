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
    <Card className="space-y-4">
      <CardHeader className="border-b border-border py-3 px-4 flex flex-row items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-primary" />
          <CardTitle className="text-xs uppercase tracking-wider">
            Attack Surface Topology
          </CardTitle>
        </div>
        <Badge variant="outline">
          {assets.length} Hosts · {services.length} Services
        </Badge>
      </CardHeader>

      <CardContent className="space-y-4 p-4 font-mono">
        {/* Discovered Assets */}
        <div>
          <div className="text-[11px] text-muted-foreground uppercase tracking-wider mb-2">
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
                  className="gap-1.5 px-2.5 py-1 text-xs font-semibold"
                >
                  <Server className="h-3 w-3 text-primary" />
                  {asset}
                </Badge>
              ))
            )}
          </div>
        </div>

        {/* Discovered Open Services */}
        <div>
          <div className="text-[11px] text-muted-foreground uppercase tracking-wider mb-2">
            Open Services & Versions
          </div>
          <div className="space-y-2">
            {services.length === 0 ? (
              <span className="text-xs text-muted-foreground">Recon in progress...</span>
            ) : (
              services.map((svc, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between rounded-md border border-border bg-muted/40 p-2.5 text-xs"
                >
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="font-bold">
                      Port {svc.port}
                    </Badge>
                    <span className="text-foreground font-medium">
                      {svc.service || svc.product || "HTTP Service"}
                    </span>
                  </div>
                  {svc.version && (
                    <span className="text-muted-foreground text-[11px] bg-background px-2 py-0.5 rounded border border-border">
                      v{svc.version}
                    </span>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
