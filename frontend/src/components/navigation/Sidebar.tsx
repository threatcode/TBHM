import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  Shield,
  Target,
  Scan,
  Activity,
  FileText,
  Settings,
} from "lucide-react";

const navigation = [
  { name: "Dashboard", href: "/", icon: Shield },
  { name: "Targets", href: "/targets", icon: Target },
  { name: "Scans", href: "/scans", icon: Scan },
  { name: "Findings", href: "/findings", icon: Activity },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "Settings", href: "/settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <div className="flex h-screen w-64 flex-col border-r border-slate-800 bg-slate-950">
      <div className="flex h-16 items-center border-b border-slate-800 px-6">
        <Shield className="h-6 w-6 text-blue-400" />
        <span className="ml-2 text-lg font-bold text-slate-100">TBHM</span>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-4">
        {navigation.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-slate-800 text-slate-100"
                  : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
              )}
            >
              <item.icon className="h-5 w-5" />
              {item.name}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-slate-800 p-4">
        <p className="text-xs text-slate-500">v0.1.0</p>
      </div>
    </div>
  );
}

export default Sidebar;