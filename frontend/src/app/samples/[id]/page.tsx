import {AuthGate} from '@/components/common';
import {SamplePage} from '@/components/workspace-pages';
export default async function Page({params}:{params:Promise<{id:string}>}){const {id}=await params;return <AuthGate><SamplePage id={id}/></AuthGate>}
