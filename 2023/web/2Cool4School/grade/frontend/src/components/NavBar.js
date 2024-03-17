import * as React from 'react';
import AppBar from '@mui/material/AppBar';
import Box from '@mui/material/Box';
import Toolbar from '@mui/material/Toolbar';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import Menu from '@mui/material/Menu';
import MenuIcon from '@mui/icons-material/Menu';
import Container from '@mui/material/Container';
import Avatar from '@mui/material/Avatar';
import Button from '@mui/material/Button';
import Tooltip from '@mui/material/Tooltip';
import MenuItem from '@mui/material/MenuItem';
import SchoolIcon from '@mui/icons-material/School';
import { useNavigate } from "react-router-dom"
import { logout } from '../api/Auth';


class ResponsiveAppBar extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorElNav: null,
      anchorElUser: null
    };
  }

  handleOpenNavMenu = (event) => {
    this.setState({
      anchorElNav: event.currentTarget
    });
  };

  handleOpenUserMenu = (event) => {
    this.setState({
      anchorElUser: event.currentTarget
    });
  };

  handleCloseNavMenu = () => {
    this.setState({
      anchorElNav: null
    });
  };

  handleCloseUserMenu = () => {
    this.setState({
      anchorElUser: null
    });
  };

  handleLogout = () => {
    logout()
    this.handleCloseUserMenu();
  };

  render() {
    return (
      <AppBar position="static">
        <Container maxWidth="xl">
          <Toolbar disableGutters>
            <SchoolIcon sx={{ display: { xs: 'none', md: 'flex' }, mr: 1 }} onClick={() => this.props.navigate('/')} />
            <Typography
              variant="h6"
              noWrap
              component="a"
              sx={{
                mr: 2,
                display: { xs: 'none', md: 'flex' },
                fontWeight: 700,
                color: 'inherit',
                textDecoration: 'none',
                cursor: 'pointer'
              }}
              onClick={() => this.props.navigate('/')}
            >
              Some University
            </Typography>
            {this.props.user && !this.props.user.isNew && this.props.ready && this.props.user.role !== 'teacher' ?
              <Box sx={{ flexGrow: 1, display: { xs: 'flex', md: 'none' } }}>
                <IconButton
                  size="large"
                  aria-label="account of current user"
                  aria-controls="menu-appbar"
                  aria-haspopup="true"
                  onClick={this.handleOpenNavMenu}
                  color="inherit"
                >
                  <MenuIcon />
                </IconButton>
                <Menu
                  id="menu-appbar"
                  anchorEl={this.state.anchorElNav}
                  anchorOrigin={{
                    vertical: 'bottom',
                    horizontal: 'left',
                  }}
                  keepMounted
                  transformOrigin={{
                    vertical: 'top',
                    horizontal: 'left',
                  }}
                  open={Boolean(this.state.anchorElNav)}
                  onClose={this.handleCloseNavMenu}
                  sx={{
                    display: { xs: 'block', md: 'none' },
                  }}
                >
                  {this.props.pages.map((page) => (
                    <MenuItem key={page} onClick={(e) => { this.handleCloseNavMenu(e); this.props.navigate("/" + page.toLowerCase()) }}>
                      <Typography textAlign="center">{page}</Typography>
                    </MenuItem>
                  ))}
                </Menu>
              </Box>
              :
              null
            }
            <SchoolIcon sx={{ display: { xs: 'flex', md: 'none' }, mr: 1 }} />
            <Typography
              variant="h5"
              noWrap
              component="a"
              href=""
              sx={{
                mr: 2,
                display: { xs: 'flex', md: 'none' },
                flexGrow: 1,
                fontWeight: 700,
                color: 'inherit',
                textDecoration: 'none',
              }}
            >
              Some University
            </Typography>

            {/* Routes - requires login */}
            {this.props.user && !this.props.user.isNew && this.props.ready ?
              <Box sx={{ flexGrow: 1, display: { xs: 'none', md: 'flex' } }}>
                {this.props.pages.map((page) => (
                  <Button
                    key={page}
                    onClick={(e) => { this.handleCloseNavMenu(e); this.props.navigate("/" + page.toLowerCase()) }}
                    sx={{ my: 2, color: 'white', display: 'block' }}
                  >
                    {page}
                  </Button>
                ))}
              </Box>
              : <Box sx={{ flexGrow: 1, display: { xs: 'none', md: 'flex' } }}></Box>}

            {/* Profile and settings menu - requires login */}
            {this.props.user && !this.props.user.isNew && this.props.ready ?
              <Box sx={{ flexGrow: 0 }}>
                <Tooltip title="Open settings">
                  <IconButton onClick={this.handleOpenUserMenu} sx={{ p: 0 }}>
                    <Avatar alt={this.props.user?.name} src={this.props.user?.picture || 'none'} />
                  </IconButton>
                </Tooltip>
                <Menu
                  sx={{ mt: '45px' }}
                  id="menu-appbar"
                  anchorEl={this.state.anchorElUser}
                  anchorOrigin={{
                    vertical: 'top',
                    horizontal: 'center',
                  }}
                  keepMounted
                  transformOrigin={{
                    vertical: 'top',
                    horizontal: 'center',
                  }}
                  open={Boolean(this.state.anchorElUser)}
                  onClose={this.handleCloseUserMenu}
                >
                  {
                    this.props.user.role === 'student' ?
                      <MenuItem key='Profile' onClick={(e) => { this.handleCloseNavMenu(e); this.props.navigate("/profile") }}>
                        <Typography textAlign="center">Profile</Typography>
                      </MenuItem>
                      :
                      null
                  }

                  <MenuItem key='Logout' onClick={this.handleLogout}>
                    <Typography textAlign="center">Logout</Typography>
                  </MenuItem>
                </Menu>
              </Box>
              : null 
            }
            {this.props.user || !this.props.ready ?
              null :
              /* login button if not logged in */
              <Button color="inherit" href={"/login"}>Login</Button>
            }
          </Toolbar>
        </Container>
      </AppBar>
    );
  }
};

function WithNavigate(props) {
  let navigate = useNavigate();
  return <ResponsiveAppBar {...props} navigate={navigate} />
}

export default WithNavigate;
