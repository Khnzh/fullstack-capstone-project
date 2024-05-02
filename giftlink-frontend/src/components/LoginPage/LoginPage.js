import React, { useState, useEffect } from 'react';
import './LoginPage.css';
import { useAppContext } from '../../context/AuthContext';
import { useNavigate } from 'react-router-dom';

function LoginPage() {
    //insert code here to create useState hook variables for email, password
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [incorrect, setIncorrect] = useState('')

    const navigate = useNavigate()
    const bearerToken = sessionStorage.getItem('bearer-token');
    const { setIsLoggedIn } = useAppContext();

    useEffect(() => {
      if (sessionStorage.getItem('auth-token')) {
        navigate('/app')
      }
    }, [navigate])

    
    // insert code here to create handleLogin function and include console.log
    let response;
    const handleLogin = async () => {
        try {
        response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/auth/login`,{
            method: 'POST',
            headers: {
              'content-type' : 'application/json',
              'Authorization' : bearerToken ? `Bearer ${bearerToken}` : '',
            },
            body: JSON.stringify({
                email: email,
                password: password,
            })
        })} catch(e) {
            console.log("Error fetching details: " + e)
        }

        try{
            const json = await response.json();
            if (json.authtoken){
                sessionStorage.setItem('auth-token', json.authtoken);
                sessionStorage.setItem('name', json.name);
                sessionStorage.setItem('email', json.email);
                setIsLoggedIn(true);
                navigate('/app')
              } else {
                document.getElementById("email").value="";
                document.getElementById("password").value="";
                setIncorrect("Wrong password. Try again.");
                setTimeout(() => {
                  setIncorrect("");
                }, 2000);
              }
              if (json.error) {
                
                console.log ("Error showing response: " + json.error)
            }
        } catch(e) {
            console.log ("Error showing response: " + e)
        }
    };

        return (
      <div className="container mt-5">
        <div className="row justify-content-center">
          <div className="col-md-6 col-lg-4">
            <div className="login-card p-4 border rounded">
              <h2 className="text-center mb-4 font-weight-bold">Login</h2>

          {/* insert code here to create input elements for the variables email and  password */}
          <div className="mb-4">
                <label htmlFor="email" className="form label">Email</label><br></br>
                <input
                id="email"
                type="email"
                className="form-control"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                />
                <label htmlFor="password" className="form label">Password</label><br></br>
                <input
                id="password"
                type="password"
                className="form-control"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                />
                <span style={{color:'red',height:'.5cm',display:'block',fontStyle:'italic',fontSize:'12px'}}>{incorrect}</span>
            </div>
            <button className="btn btn-primary w-100 mb-3" onClick={handleLogin}>Login</button>

          {/* insert code here to create a button that performs the `handleLogin` function on click */}
                <p className="mt-4 text-center">
                    New here? <a href="/app/register" className="text-primary">Register Here</a>
                </p>

            </div>
          </div>
        </div>
      </div>
    )
}

export default LoginPage;