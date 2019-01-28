package ru.springbootstrap.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import ru.springbootstrap.model.Role;
import ru.springbootstrap.model.User;
import ru.springbootstrap.service.abstraction.role.RoleService;
import ru.springbootstrap.service.abstraction.user.UserService;

import javax.persistence.NoResultException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Controller
public class HomeController {
	@Autowired
	private UserService userService;
	@Autowired
	private RoleService roleService;

	@RequestMapping(value = { "/", "/welcome**" }, method = RequestMethod.GET)
	public String getWelcome(ModelMap modelMap) {
		modelMap.addAttribute("adminRole", new Role("Admin"));
		modelMap.addAttribute("userRole", new Role("User"));
		modelMap.addAttribute("adminName", getPrincipal());
		modelMap.addAttribute("users", userService.getAllUsers());
		return "welcome";
	}

	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String loginPage(ModelMap modelMap) {
	    return "login";
	}



	@RequestMapping("/test")
	public String getIndex(Model model){
		List<User> users = userService.getAllUsers();
		model.addAttribute("users", users);
        model.addAttribute("name", "TEST");
		return "index";
	}

	@RequestMapping(value="/admin/allusers", method = RequestMethod.GET)
	public String allUsersGet(Model model){
		List<User> users = userService.getAllUsers();
		model.addAttribute("adminRole", new Role("Admin"));
		model.addAttribute("userRole", new Role("User"));
		model.addAttribute("adminName", getPrincipal());
		model.addAttribute("users", users);
		return "allusers";
	}



	@RequestMapping(value="/admin/adduser", method= RequestMethod.POST)
	public String saveUser     (@RequestParam(value = "name") String name,
							  @RequestParam(value = "login") String login,
							  @RequestParam(value = "password") String password,
							  @RequestParam(value = "role") Set<Role> roles) throws UsernameNotFoundException {
		if (roles.size() == 0) {
			return "redirect:/admin/allusers?error";
		} else if (password.equals("")) {
			return "redirect:/admin/allusers?error";
		} else if (login.equals("")) {
			return "redirect:/admin/allusers?error";
		} else if (name.equals("")) {
			return "redirect:/admin/allusers?error";
		}
		Set<Role> roleSet = new HashSet<>();
		for (Role role : roles) {
			try {
				roleSet.add(roleService.getByRoleName(role.getRoleName()));
			} catch (NoResultException exp) {

			}
		}
		User user = new User(name, login, password, roleSet);

		userService.saveUser(user);
		return "redirect:/admin/allusers";
	}


	@RequestMapping(value="/admin/deluser/{id}", method = RequestMethod.GET)
		public String delUser(@PathVariable("id") long id, Model model){
		long userIdToDel = id;
		userService.deleteUser(userIdToDel);
		List<User> users = userService.getAllUsers();
		model.addAttribute("users", users);
		return "redirect:/admin/allusers";
	}

	@RequestMapping(value="/admin/edituser/{id}", method = RequestMethod.GET)
	public String editUser(@PathVariable("id") long id, Model model) {
		long userIdToEdit = id;
		User userToEdit =  userService.getUserById(userIdToEdit);
		model.addAttribute("user", userToEdit);
		return "edituser";
	}

	@RequestMapping(value="/admin/edit/{id}", method = RequestMethod.GET)
	public String editPage(@PathVariable("id") long id, Model model) {
		long userIdToEdit = id;
		User userToEdit =  userService.getUserById(userIdToEdit);
		model.addAttribute("user", userToEdit);
		return "edit";
	}




	@RequestMapping(value = { "/admin/edit" }, method = RequestMethod.POST)
	public String updateUser(@RequestParam(value = "id") Long id,
							 @RequestParam(value = "login") String login,
							 @RequestParam(value = "name") String name,
							 @RequestParam(value = "password") String password,
							 @RequestParam(value = "role") Set<Role> roles) {
		if (roles.size() == 0) {
			return "redirect:/admin/edit/" + id.toString() + "?error";
		} else if (password.equals("")) {
			return "redirect:/admin/edit/" + id.toString() + "?error";
		} else if (login.equals("")) {
			return "redirect:/admin/edit/" + id.toString() + "?error";
		} else if (name.equals("")) {
			return "redirect:/admin/edit/" + id.toString() + "?error";
		}
		Set<Role> roleSet = new HashSet<>();
		for (Role role : roles) {
			try {
				roleSet.add(roleService.getByRoleName(role.getRoleName()));
			} catch (NoResultException exp) {

			}
		}
		User user = new User(id, name, login, password, roleSet);
		userService.editUser(user);
		return "redirect:/admin";
	}


/*	@RequestMapping(value = { "/admin/edit" }, method = RequestMethod.POST)
	public String updateUser(@RequestParam(value = "id") String id,
							 @RequestParam(value = "Login1") String login,
							 @RequestParam(value = "Name2") String name,
							 @RequestParam(value = "Password3") String password,
							 @RequestParam(value = "Role4") Set<Role> roles) {
		if (roles.size() == 0) {
			return "redirect:/admin/edit/" + id.toString() + "?error";
		} else if (password.equals("")) {
			return "redirect:/admin/edit/" + id.toString() + "?error";
		} else if (login.equals("")) {
			return "redirect:/admin/edit/" + id.toString() + "?error";
		} else if (name.equals("")) {
			return "redirect:/admin/edit/" + id.toString() + "?error";
		}
		Set<Role> roleSet = new HashSet<>();
		for (Role role : roles) {
			try {
				roleSet.add(roleService.getByRoleName(role.getRoleName()));
			} catch (NoResultException exp) {

			}
		}
		long iD = Long.parseLong(id);
		User user = new User(iD, name, login, password, roleSet);

		userService.editUser(user);
		return "redirect:/admin";
	}  */
	



	@RequestMapping(value = "/user", method = RequestMethod.GET)
	public String userPage(ModelMap modelMap) {
		modelMap.addAttribute("user", getPrincipal());
		return "user";
	}

	@RequestMapping(value = "/admin", method = RequestMethod.GET)
	public String adminPage(ModelMap modelMap) throws Exception {
		modelMap.addAttribute("adminRole", new Role("Admin"));
		modelMap.addAttribute("userRole", new Role("User"));
		modelMap.addAttribute("adminName", getPrincipal());
		modelMap.addAttribute("users", userService.getAllUsers());
		return "admin";
	}


	@RequestMapping(value = "/admin/add", method = RequestMethod.GET)
	public String addUserPage(ModelMap modelMap) {
		return "add";
	}


	@RequestMapping(value = "/admin/add", method = RequestMethod.POST)
	public String addUserPage(@RequestParam(value = "name") String name,
							  @RequestParam(value = "login") String login,
							  @RequestParam(value = "password") String password,
							  @RequestParam(value = "role") Set<Role> roles) throws UsernameNotFoundException {
		if (roles.size() == 0) {
			return "redirect:/admin/add?error";
		} else if (password.equals("")) {
			return "redirect:/admin/add?error";
		} else if (login.equals("")) {
			return "redirect:/admin/add?error";
		} else if (name.equals("")) {
			return "redirect:/admin/add?error";
		}
		Set<Role> roleSet = new HashSet<>();
		for (Role role : roles) {
			try {
				roleSet.add(roleService.getByRoleName(role.getRoleName()));
			} catch (NoResultException exp) {

			}
		}
		User user = new User(name, login, password, roleSet);

		userService.saveUser(user);
		return "redirect:/admin";
	}


	private String getPrincipal() {
		String userName = null;
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

		if (principal instanceof User) {
			userName = ((User) principal).getUsername();
		} else {
			userName = principal.toString();
		}
		return userName;
	}

	@RequestMapping(value = "/admin/delete/{id}", method = RequestMethod.GET)
	public String deleteUser(@PathVariable("id") Long id) {
		userService.deleteUser(id);
		return "redirect:/admin";
	}


	@RequestMapping(value = {  "/admin/edituser" }, method = RequestMethod.POST)
	public String saveUser(@RequestParam(value = "id") Long id,
						   @RequestParam(value = "name") String name,
						   @RequestParam(value = "login") String login,
						   @RequestParam(value = "password") String password,
						   @RequestParam(value = "role") Set<Role> roles) {
		if (roles.size() == 0) {
			return "redirect:/admin/edituser/" + id.toString() + "?error";
		} else if (password.equals("")) {
			return "redirect:/admin/edituser/" + id.toString() + "?error";
		} else if (login.equals("")) {
			return "redirect:/admin/edituser/" + id.toString() + "?error";
		} else if (name.equals("")) {
			return "redirect:/admin/edituser/" + id.toString() + "?error";
		}
		Set<Role> roleSet = new HashSet<>();
		for (Role role : roles) {
			try {
				roleSet.add(roleService.getByRoleName(role.getRoleName()));
			} catch (NoResultException exp) {

			}
		}
		User user = new User(id, name, login, password, roleSet);

		userService.editUser(user);
		return "redirect:/admin/allusers";
	}

	@RequestMapping(value = "/access_denied", method = RequestMethod.GET)
	public String deniesPage(ModelMap modelMap) {
		return "access_denied";
	}

	@RequestMapping(value = "/logout", method = RequestMethod.GET)
	public String logOut(HttpServletRequest request, HttpServletResponse response) {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null) {
			new SecurityContextLogoutHandler().logout(request, response, auth);
		}
		return "redirect:/login?logout";
	}


	@RequestMapping(value = "/registration", method = RequestMethod.GET)
	public String registrationPage(ModelMap modelMap) {
		return "registration";
	}

	@RequestMapping(value = "/registration", method = RequestMethod.POST)
	public String addUser(@RequestParam(value = "name") String name,
						  @RequestParam(value = "login") String login,
						  @RequestParam(value = "password") String password,
						  @RequestParam(value = "role") Set<Role> roles) throws UsernameNotFoundException {
		if (roles.size() == 0) {
			return "redirect:/registration?error";
		} else if (password.equals("")) {
			return "redirect:/registration?error";
		} else if (login.equals("")) {
			return "redirect:/registration?error";
		} else if (name.equals("")) {
			return "redirect:/registration?error";
		}
		Set<Role> roleSet = new HashSet<>();
		for (Role role : roles) {
			try {
				roleSet.add(roleService.getByRoleName(role.getRoleName()));
			} catch (NoResultException exp) {

			}
		}
		User user = new User(name, login, password, roleSet);

		userService.saveUser(user);
		return "redirect:/";
	}


}
