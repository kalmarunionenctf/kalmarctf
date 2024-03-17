import * as React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { getUser } from './api/Auth';
import Home from "./pages/Home";
import Grades from "./pages/Grades";
import Profile from "./pages/Profile";
import NewUser from "./pages/NewUser";
import NotFound from "./pages/NotFound";
import Layout from "./Layout";

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
  },
});


class App extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      user: undefined,
      ready: false
    };
  }

  async componentDidMount() {
    try {
      const user = await getUser();
      this.setState({ user });
    } catch (e) {}
    this.setState({ ready: true });
  }

  updateUser = async () => {
    const user = await getUser();
    this.setState({ user });
  }

  render() {
    return (
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <Router>
          <Routes>
            <Route path="/" element={<Layout user={this.state.user} ready={this.state.ready} pages={['Grades']} />}>
              {
                this.state.user ? 
                  (this.state.user.role === 'teacher' ?
                    <>
                    <Route index element={<Home />} />
                    <Route path="grades/:id" element={<Grades user={this.state.user} />} />
                    </> 
                  :
                    (this.state.user.isNew ?
                      <>
                      <Route index element={<NewUser callback={this.updateUser} />} />
                      </>
                    :
                        <>
                        <Route index element={<Home />} />
                        <Route path="grades" element={<Grades user={this.state.user} />} />
                        <Route path="profile" element={<Profile user={this.state.user} />} />
                        <Route path="*" element={<NotFound />} />
                        </>
                    )
                  )
                :
                  <>
                    <Route index element={<Home />} />
                    <Route path="*" element={<Home />} />
                  </>
              }
              
            </Route>
          </Routes>
        </Router>
      </ThemeProvider>
    );
  }
}

export default App;

/*
<header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Edit <code>src/App.js</code> and save to reload.
        </p>
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn React
        </a>
      </header>
      */