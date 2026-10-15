import {AuthGate} from '@/components/common';
import {SamplesPage} from '@/components/workspace-pages';
export default function Page(){return <AuthGate><SamplesPage/></AuthGate>}
