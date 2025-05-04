import {FC, useRef, useState} from "react";
import "./Dropdown.css";
import {CSSTransition} from "react-transition-group";
import * as React from "react";
import SettingsSvg from '../icons/settings.svg?react';
import BackSvg from '../icons/back.svg?react';
import LoginSvg from '../icons/login.svg?react';
import {NavLink} from "react-router-dom";

interface Props {
    children: React.ReactNode;
    leftIcon: React.ReactNode;
    rightIcon: React.ReactNode;
    url: string;
    goToMenu: string;
}

export const Dropdown: FC = () => {

    const [activeMenu, setActiveMenu] = useState("main");
    const nodeRefMain = useRef<HTMLDivElement>(null);
    const nodeRefSettings = useRef<HTMLDivElement>(null);
    const menuRef = useRef<HTMLDivElement>(null);

    const DropdownItem: FC<Props> = (props) => {
        return (
            <NavLink to={props.url} className={"menu-item"} onClick={() => props.goToMenu && setActiveMenu(props.goToMenu)}>
                <span className={"icon-button"}>{props.leftIcon}</span>
                {props.children}
                <span className={"icon-right"}>{props.rightIcon}</span>
            </NavLink>
        )
    }

    function calcHeight(el: HTMLDivElement | null) {
        const menu = menuRef.current;
        if (el && menu) {
            menu.style.height = `${el.scrollHeight}px`;
        }
    }

    return (
        <div ref={menuRef} className={"dropdown"}>
            <CSSTransition in={activeMenu === "main"}
                           unmountOnExit={true}
                           nodeRef={nodeRefMain}
                           timeout={500}
                           classNames={"menu-primary"}
                           onEnter={() => {calcHeight(nodeRefMain.current)}}>
                <div ref={nodeRefMain} className={"menu"}  >
                    <DropdownItem url={""} leftIcon={<SettingsSvg/>} rightIcon={""} goToMenu={"settings"} >
                        Settings
                    </DropdownItem>
                    <DropdownItem url={"/login"} leftIcon={<LoginSvg/>} rightIcon={""} goToMenu={""}>
                        Login
                    </DropdownItem>
                </div>
            </CSSTransition>

            <CSSTransition in={activeMenu === "settings"} unmountOnExit={true} nodeRef={nodeRefSettings} timeout={500} classNames={"menu-secondary"}
                           onEnter={() => {calcHeight(nodeRefSettings.current)}}
            >
                <div ref={nodeRefSettings} className={"menu"} >
                    <DropdownItem url={""} goToMenu={"main"} leftIcon={<BackSvg/>} rightIcon={""}>
                        Back
                    </DropdownItem>
                    <DropdownItem url={""} goToMenu={"main"} leftIcon={""} rightIcon={""}>
                        My Profile
                    </DropdownItem>
                    <DropdownItem url={""} goToMenu={"main"} leftIcon={""} rightIcon={""}>
                        Login
                    </DropdownItem>
                    <DropdownItem url={""} goToMenu={"main"} leftIcon={""} rightIcon={""}>
                        Logout
                    </DropdownItem>
                </div>
            </CSSTransition>
        </div>

    )
}

