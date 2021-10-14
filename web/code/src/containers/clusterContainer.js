import {bindActionCreators} from 'redux'
import {connect} from 'react-redux'

import ClusterPage from '../pages/clusterPage';


//将state.counter绑定到props的counter
function mapStateToProps(state) {
    return state;
}

//将action的所有方法绑定到props上
// function mapDispatchToProps(dispatch) {
//     return bindActionCreators(Actions, dispatch);
// }

//通过react-redux提供的connect方法将我们需要的state中的数据和actions中的方法绑定到props上

export const ClusterPageComp = connect(mapStateToProps)(ClusterPage);