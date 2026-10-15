import {AuthGate} from '@/components/common';
import {RulesPage} from '@/components/workspace-pages';
export default function Page(){return <AuthGate><RulesPage/></AuthGate>}
