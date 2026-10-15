import type {Metadata} from 'next';
import './globals.css';
import {Providers} from '@/components/providers';
import {Shell} from '@/components/shell';
export const metadata:Metadata={title:'SentinelScan — Threat analysis workspace',description:'Evidence-led executable analysis. Real engines. Transparent verdicts.'};
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="en"><body><Providers><Shell>{children}</Shell></Providers></body></html>}
