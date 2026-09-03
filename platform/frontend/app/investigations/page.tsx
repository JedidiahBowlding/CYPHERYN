"use client";

import Link from "next/link";
import {useEffect,useState} from "react";
import DashboardNav from "../_components/DashboardNav";
import {platformApiUrl} from "../_lib/platformApi";

const API=platformApiUrl();
const headers={"X-Dev-Subject":"local-analyst","X-Dev-Email":"analyst@cypheryn.local"};
type Investigation={id:string;name:string;description:string;status:string;created_at:string;last_scanned_at:string|null};

export default function Investigations(){
  const[rows,setRows]=useState<Investigation[]>([]);
  const[loading,setLoading]=useState(true);
  const[error,setError]=useState("");
  useEffect(()=>{let active=true;(async()=>{try{const organizations=await fetch(`${API}/api/v1/organizations`,{headers}).then(response=>{if(!response.ok)throw new Error("Organizations could not be loaded");return response.json()});const groups=await Promise.all(organizations.map((organization:{id:string})=>fetch(`${API}/api/v1/organizations/${organization.id}/investigations`,{headers}).then(response=>response.json())));if(active)setRows(groups.flat().sort((a:Investigation,b:Investigation)=>Date.parse(b.last_scanned_at??b.created_at)-Date.parse(a.last_scanned_at??a.created_at)))}catch(cause){if(active)setError(cause instanceof Error?cause.message:"Investigations could not be loaded")}finally{if(active)setLoading(false)}})();return()=>{active=false}},[]);
  return <main className="section-page list-page"><DashboardNav/><section className="section-main list-dashboard-main"><div className="list-wrap"><section className="list-intro"><div><p className="eyebrow">Workspace</p><h1>Investigations</h1><p>Authorized scopes, collection activity, findings, and evidence in one place.</p></div><div className="list-stats"><span><strong>{rows.filter(row=>row.status==="active").length}</strong>Active</span><span><strong>{rows.length}</strong>Total</span><span><strong>Newest</strong>First</span></div></section><section className="investigation-table"><header><span>Investigation</span><span>Status</span><span>Last scanned</span><span>Created</span><span/></header>{loading&&<div className="list-message">Loading investigations…</div>}{error&&<div className="list-message error">{error}</div>}{!loading&&!error&&rows.length===0&&<div className="list-message">No investigations yet.</div>}{rows.map(row=><Link className="investigation-row" href={`/investigations/${row.id}`} key={row.id}><span><i>{row.name.slice(0,2).toUpperCase()}</i><span><strong>{row.name}</strong><small>{row.description||"Authorized investigation"}</small><small className="investigation-recency-mobile">Last scanned: {row.last_scanned_at?new Date(row.last_scanned_at).toLocaleString():"Never"}</small></span></span><span><b className={row.status==="active"?"monitoring":"review"}>{row.status}</b></span><span><time dateTime={row.last_scanned_at??undefined} title={row.last_scanned_at?new Date(row.last_scanned_at).toLocaleString():"No completed scans"}>{row.last_scanned_at?new Date(row.last_scanned_at).toLocaleString():"Never"}</time></span><span><time dateTime={row.created_at} title={new Date(row.created_at).toLocaleString()}>{new Date(row.created_at).toLocaleDateString()}</time></span><span>›</span></Link>)}</section></div></section></main>;
}
