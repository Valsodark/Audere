import {FC} from "react";
import {Navbar} from "../component";
import {NavItem} from "../component/Navigation.tsx";
import {Dropdown} from "../component/Dropdown.tsx";
import ProfileSvg from '../icons/profile.svg?react';

export const Home: FC = () => {
    return (
        <>
            <Navbar>
                <NavItem url={""} name={<ProfileSvg/>}>
                    <Dropdown></Dropdown>
                </NavItem>
            </Navbar>
        </>
    )
}