import {FC} from "react";

import "./Login.css"
import {Navbar} from "../component";
import {NavItem} from "../component/Navigation.tsx";
import {Dropdown} from "../component/Dropdown.tsx";
import SettingsSvg from "../icons/settings.svg?react"

export const Login: FC = () => {
    return (
        <>
            <Navbar name={""} url={""}>
                <NavItem url={"/"} name={"😀"}> </NavItem>
                <NavItem url={"*"} name={"😀"}> </NavItem>
                <NavItem url={""} name={<SettingsSvg/>}>
                    <Dropdown></Dropdown>
                </NavItem>
            </Navbar>
            <div className={"holder"}>
                <form className="form">
              <span className="input-span">
                <label htmlFor="email" className="label">Email</label>
                <input type="email" name="email" id="email"/></span>
                    <span className="input-span">
                <label htmlFor="password" className="label">Password</label>
                <input type="password" name="password" id="password"/></span>
                    <span className="span"><a href="#">Forgot password?</a></span>
                    <input className="submit" type="submit" value="Log in"/>
                    <span className="span">Don't have an account? <a href="#">Sign up</a></span>
                </form>
            </div>
        </>
    )
}