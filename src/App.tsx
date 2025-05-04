import {Route, Routes} from "react-router-dom";
import {Home, Login, NotFound} from "./pages";

function App() {


  return (
    <>
        <Routes>
            <Route path={"/"} element={<Home/>}></Route>
            <Route path={"/login"} element={<Login/>}></Route>
            <Route path={"*"} element={<NotFound/>}></Route>
        </Routes>
    </>
  )
}

// styles Chango, Inclusive Sans

export default App
