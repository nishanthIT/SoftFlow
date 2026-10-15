import {AuthGate} from '@/components/common';
import {UploadPage} from '@/components/upload';
export default function Page(){return <AuthGate><UploadPage/></AuthGate>}
