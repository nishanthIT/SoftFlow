import {AuthGate} from '@/components/common';
import {AnalysisPage} from '@/components/analysis';
export default async function Page({params}:{params:Promise<{id:string}>}){const {id}=await params;return <AuthGate><AnalysisPage id={id} report/></AuthGate>}
