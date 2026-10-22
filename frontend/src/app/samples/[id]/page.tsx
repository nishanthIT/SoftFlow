import {SamplePage} from '@/components/workspace-pages';
export default async function Page({params}:{params:Promise<{id:string}>}){const {id}=await params;return <SamplePage id={id}/>}
