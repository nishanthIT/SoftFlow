import {AuthGate} from '@/components/common';
import {Dashboard} from '@/components/dashboard';
export default function Page(){return <AuthGate><Dashboard/></AuthGate>}
