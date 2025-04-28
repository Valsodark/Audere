import {FC, useState} from "react";
import {Button, LoginButton} from "./Button.tsx";
import "./Navbar.css"

export const Navbar: FC = () => {
    const [menuOpen,setMenuOpen] = useState(false)
    return (
        <nav>
            <label className="burger" htmlFor="burger" onChange={() => {
                setMenuOpen(!menuOpen)
            }}>
                <input type="checkbox" id="burger"/>
                <span></span>
                <span></span>
                <span></span>
            </label>
            <div className={"home-bar"}>
                <img className={"panel-logo"} src="/audere-panel.png"/>
                <ul className={menuOpen ? "open" : ""}>
                    <li><Button url={"/"} name={"Home"}/></li>
                    <li><Button url={"https://norris.audere.club/"} name={"Chuck Norris"}/></li>
                    <li><Button url={"*"} name={"Currency Convertor"}/></li>
                    <li><Button url={"*"} name={"Food Delivery"}/></li>
                    <li><Button url={"*"} name={"Minecraft"}/></li>
                </ul>
            </div>
            <LoginButton url={"/"} name={"Home"}/>
        </nav>
    )
}