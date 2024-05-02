import React, {useEffect} from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAppContext } from '../../context/AuthContext';

export default function Navbar() {
    const {isLoggedIn, setIsLoggedIn, userName, setUserName} = useAppContext();

    const navigate = useNavigate();

    useEffect(()=>{
        const authTokenFromSession = sessionStorage.getItem("auth-token")
        const nameFromSession = sessionStorage.getItem("name")
        if (authTokenFromSession) {
            if (nameFromSession&&isLoggedIn) {
                setUserName(nameFromSession)
            } else {
                sessionStorage.removeItem("authtoken");
                sessionStorage.removeItem("name");
                sessionStorage.removeItem("email");
                setIsLoggedIn(false);
            }
        }
    }, [setUserName, isLoggedIn, setIsLoggedIn])

    const handleLogout=()=>{
        sessionStorage.removeItem('auth-token');
        sessionStorage.removeItem('name');
        sessionStorage.removeItem('email');
        setIsLoggedIn(false);
        navigate(`/app`);
    }

    const profileSecton=()=>{
        navigate(`/app/profile`);
    }

    return (
        <nav className="navbar navbar-expand-lg navbar-light bg-light">
            <Link className="navbar-brand" to="/">GiftLink</Link>
            <div className="collapse navbar-collapse" id="navbarNav">
                <ul className="navbar-nav">
                <li className="nav-item"><Link className="nav-link" to="/home.html">Home</Link></li>
                <li className="nav-item"><Link className="nav-link" to="/app">Gifts</Link></li>
                <li className="nav-item">
                    <Link className="nav-link" to="/app/search">Search</Link>
                </li>
                <ul className="navbar-nav ml-auto">
                {isLoggedIn ? (
                                        <>
                                        <li className="nav-item"> <span className="nav-link" style={{color: "black", cursor:"pointer"}} onClick={profileSecton}>Welcome, {userName}</span> </li>
                                        <li className="nav-item"><button className="nav-link login-btn" onClick={handleLogout}>Logout</button></li>
                                        </>
                                        )  : (
                                        <>
                                            <li className="nav-item">
                                            <Link className="nav-link login-btn" to="/app/login">Login</Link>
                                            </li>
                                            <li className="nav-item">
                                            <Link className="nav-link register-btn" to="/app/register">Register</Link>
                                            </li>
                                        </>
                                    )
                                    }
                </ul>
                </ul>
            </div>
        </nav>
    );
}
