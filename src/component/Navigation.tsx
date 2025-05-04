import {FC, useState} from "react";
import "./Navbar.css"
import * as React from "react";
import {NavLink} from "react-router-dom";
import MinecraftSvg from "../icons/minecraft.svg?react"
import ConvertortSvg from "../icons/currency-convertor.svg?react"
import TakeAwaySvg from "../icons/takeaway.svg?react"
import ChuckSvg from "../icons/chuck.svg?react"

interface Props {
    children: React.ReactNode
}
interface Utilities {
    children?: React.ReactNode,
    name : React.ReactNode,
    url : string
}

export const Navbar: FC<Props> = (props) => {
    return (
        <nav className={"navbar"}>
            <ul className={"navbar-nav"}>
                <div className={"navbar-nav-lg"}>
                    <NavLink className={"logo-link"} to={"/"}>
                        <img src={"audere-panel.png"} alt={"audere-panel.png"} className={"logo"}/>
                    </NavLink>
                    <div className={"nav-redirects-lg"}>
                        <NavMenu></NavMenu>
                    </div>
                    <div className={"nav-items"}>
                        {props.children}
                    </div>
                </div>
                <div className={"navbar-nav-md"}>
                    <NavMenu></NavMenu>
                </div>
            </ul>
        </nav>
    )
}

export const NavItem: FC<Utilities> = (utility) =>{

    const [open, setOpen] = useState(false);

    return (
        <li className={"nav-item"}>
            <NavLink className={"icon-button"} to={utility.url} onClick={() => setOpen(!open)}>{utility.name}</NavLink>
            {open && utility.children}
        </li>
    )
}
export const NavMenu: FC = () =>{
    return (
        <ul className={"nav-menu"}>
            <NavMenuItem url={""} name={<ChuckSvg/>}></NavMenuItem>
            <NavMenuItem url={""} name={<MinecraftSvg/>}></NavMenuItem>
            <NavMenuItem url={""} name={<ConvertortSvg/>}></NavMenuItem>
            <NavMenuItem url={""} name={<TakeAwaySvg/>}></NavMenuItem>

        </ul>
    )
}

export const NavMenuItem: FC<Utilities> = (utility) =>{
    return (
        <ul className={"nav-menu"}>
            <NavLink className={"nav-menu-item"} to={utility.url} >{utility.name}</NavLink>
        </ul>
    )
}