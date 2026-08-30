import type {Metadata} from "next";
import InvestigationWorkspace from "./workspace";
export async function generateMetadata():Promise<Metadata>{return{title:"Investigation workspace — CYPHERYN",description:"Authorized scope, collection activity, entities, relationships, and evidence.",openGraph:{title:"Investigation workspace — CYPHERYN",description:"Authorized scope, collection activity, entities, relationships, and evidence.",images:[]},twitter:{title:"Investigation workspace — CYPHERYN",description:"Authorized scope, collection activity, entities, relationships, and evidence.",images:[]}}}
export default async function Detail({params}:{params:Promise<{id:string}>}){const{id}=await params;return <InvestigationWorkspace id={id}/>}
