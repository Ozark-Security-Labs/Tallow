import { PackageDetail } from './packages/PackageDetail';
import { PackageList } from './packages/PackageList';
export function Packages() { return window.location.pathname.includes('/packages/') ? <PackageDetail /> : <PackageList />; }
