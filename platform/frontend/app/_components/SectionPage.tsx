import {ReactNode} from "react";
import DashboardNav from "./DashboardNav";

export default function SectionPage({title,eyebrow,description,children,action}:{title:string;eyebrow:string;description:string;children?:ReactNode;action?:ReactNode}){return <main className="section-page"><DashboardNav/><section className="section-main"><header className="section-header"><div className="section-heading"><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="section-description">{description}</p></div>{action}</header>{children}</section></main>}
