import {AuthGate} from '@/components/common';
import {AdminPage} from '@/components/workspace-pages';
export default function Page(){return <AuthGate><AdminPage/></AuthGate>}
