import {AnalysisPage} from '@/components/analysis';
export default async function Page({params}:{params:Promise<{id:string}>}){const {id}=await params;return <AnalysisPage id={id}/>}
