import {AuthGate} from '@/components/common';
import {SettingsPage} from '@/components/workspace-pages';
export default function Page(){return <AuthGate><SettingsPage/></AuthGate>}
