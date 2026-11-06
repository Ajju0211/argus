import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 text-[11px] font-medium transition-colors focus:outline-none focus:ring-1 focus:ring-ring select-none",
  {
    variants: {
      variant: {
        default:
          "border-border bg-foreground text-background font-medium",
        secondary:
          "border-border/60 bg-muted/60 text-muted-foreground font-normal",
        destructive:
          "border-rose-500/25 bg-rose-500/10 text-rose-600 dark:text-rose-400 font-medium",
        outline:
          "text-foreground border-border/70 bg-transparent font-normal",
        success:
          "border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium",
        warning:
          "border-amber-500/25 bg-amber-500/10 text-amber-600 dark:text-amber-400 font-medium",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
